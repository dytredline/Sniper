#!/usr/bin/env python3
"""External behavior oracle for a distinct opt-in scoped ZAP spider. Never runs ZAP."""
from __future__ import annotations
import json, os, tempfile, threading, unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from scanner import normalize_target
from storage import Store

class SpiderContract(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='spider_regression_')
        self.root=Path(self.tmp.name)
        self.old_store,self.old_host,self.old_port=server.STORE,server.HOST,server.PORT
        server.STORE=Store(self.root/'data'/'sniper.db')
        server.HOST='127.0.0.1'
        self.target=server.STORE.create_target(normalize_target('https://fixture.example/'))
        now=datetime.now(timezone.utc)
        self.window=(now-timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')+'/'+(now+timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.engagement=server.STORE.create_engagement(target_id=self.target['id'],name='Fixture root crawl',authorization_ref='LOCAL-FIXTURE-AUTH',scope_notes='Fixture root only',
            out_of_scope='["/admin"]',test_window=self.window,special_approvals={})
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.SniperHandler)
        self.httpd.daemon_threads=True
        server.PORT=self.httpd.server_address[1]
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start()
        self.env=patch.dict(os.environ,{'SNIPER_DATA_DIR':str(self.root/'data')});self.env.start()
    def tearDown(self):
        self.env.stop()
        self.httpd.shutdown();self.httpd.server_close();self.thread.join(timeout=2)
        server.STORE,server.HOST,server.PORT=self.old_store,self.old_host,self.old_port
        self.tmp.cleanup()
    def body(self):
        return {'target_id':self.target['id'],'engagement_id':self.engagement['id'],'confirm_authorized':True,'confirm_crawl':True}
    def post(self,path,payload):
        req=Request('http://127.0.0.1:'+str(self.httpd.server_address[1])+path,
            data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
        try:
            with urlopen(req,timeout=5) as r:return r.status,json.loads(r.read())
        except HTTPError as e:return e.code,json.loads(e.read())
    def update(self,changes):
        self.engagement=server.STORE.update_engagement(self.engagement['id'],changes)
        self.assertIsNotNone(self.engagement)
    def fake(self):
        return {'format':'zap-target-spider-v1','profile':'same-origin-root-spider-v1','site_count':1,'alert_type_count':1,
            'instance_count':2,'risk_counts':{'informational':0,'low':1,'medium':0,'high':0},
            'report_sha256':'a'*64,'elapsed_seconds':1.25}
    def test_control_existing_active_no_consent_is_denied(self):
        body={'target_id':self.target['id'],'engagement_id':self.engagement['id'],'confirm_authorized':False,'confirm_active':False}
        with patch.object(server,'run_zap_target_active',create=True) as runner:
            status,_=self.post('/api/tool-runs/zap-target-active',body)
        self.assertEqual(status,403)
        runner.assert_not_called()
    def test_main_valid_scoped_spider_invokes_runner_and_returns_aggregate_only(self):
        expected=self.fake()
        with patch.object(server,'run_zap_target_spider',create=True,return_value=expected) as runner:
            status,data=self.post('/api/tool-runs/zap-target-spider',self.body())
        self.assertEqual(status,200)
        self.assertEqual(data,expected)
        runner.assert_called_once_with(self.target,['/admin'])
        self.assertNotIn('fixture.example',json.dumps(data))
        self.assertNotIn('LOCAL-FIXTURE-AUTH',json.dumps(data))
    def test_edge_rejects_malformed_scope_or_missing_consent_before_runner(self):
        with patch.object(server,'run_zap_target_spider',create=True) as runner:
            status,_=self.post('/api/tool-runs/zap-target-spider',{**self.body(),'confirm_crawl':False})
            self.assertEqual(status,403)
            status,_=self.post('/api/tool-runs/zap-target-spider',{**self.body(),'url':'https://other.example/'})
            self.assertEqual(status,400)
            for excluded in ('/admin','[]','["/"]','["/admin","/admin"]','["/a%2fb"]','["/foo/../bar"]','["//evil"]','["/ümlaut"]','["/foo//bar"]'):
                self.update({'out_of_scope':excluded})
                status,_=self.post('/api/tool-runs/zap-target-spider',self.body())
                self.assertIn(status,(400,403),excluded)
            runner.assert_not_called()
    def test_hidden_window_target_root_and_multiple_exclusions(self):
        expected=self.fake()
        with patch.object(server,'run_zap_target_spider',create=True,return_value=expected) as runner:
            self.update({'out_of_scope':'["/private/logs","/admin"]'})
            status,data=self.post('/api/tool-runs/zap-target-spider',self.body())
            self.assertEqual(status,200)
            self.assertEqual(data,expected)
            runner.assert_called_once_with(self.target,['/private/logs','/admin'])
        other=server.STORE.create_target(normalize_target('https://other.example/'))
        with patch.object(server,'run_zap_target_spider',create=True) as runner:
            status,_=self.post('/api/tool-runs/zap-target-spider',{**self.body(),'target_id':other['id']})
            self.assertEqual(status,403)
            self.update({'test_window':'2020-01-01T00:00:00Z/2020-01-01T01:00:00Z'})
            status,_=self.post('/api/tool-runs/zap-target-spider',self.body())
            self.assertIn(status,(400,403))
            runner.assert_not_called()
        self.update({'test_window':self.window})
        nonroot=server.STORE.create_target(normalize_target('https://fixture.example/path'))
        engagement2=server.STORE.create_engagement(target_id=nonroot['id'],name='Non-root',authorization_ref='LOCAL-FIXTURE-AUTH',scope_notes='Fixture path',
            out_of_scope='',test_window=self.window,special_approvals={})
        with patch.object(server,'run_zap_target_spider',create=True,side_effect=ValueError('non-root denied')) as runner:
            status,_=self.post('/api/tool-runs/zap-target-spider',{**self.body(),'target_id':nonroot['id'],'engagement_id':engagement2['id']})
            self.assertIn(status,(400,403))
            runner.assert_called_once()
        import zap_target_spider
        with patch.object(zap_target_spider,'_trusted_runtime') as runtime:
            with self.assertRaises(ValueError):
                zap_target_spider.run_zap_target_spider(nonroot,[])
            runtime.assert_not_called()

if __name__=='__main__':
    unittest.main(verbosity=2)
