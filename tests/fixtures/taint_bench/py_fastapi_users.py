import logging

from fastapi import APIRouter, Depends

router = APIRouter()
log = logging.getLogger("users")


@router.get("/users/{user_id}")
async def get_user(user_id: int, q: str = "", db=Depends(get_db)):
    log.info("lookup %s", user_id)
    log.info("query %s", q)  # EXPECT: LOGG-03
    user = db.get(user_id)
    contact = user.email
    log.info("notify %s", contact)  # EXPECT: LOGG-02
    log.info("notify %s", mask_email(user.email))
    db.execute(f"SELECT * FROM audit WHERE q = '{q}'")  # EXPECT: SQL
    expression = q
    return eval(expression)  # EXPECT: EVAL
