package fixture

// Kotlin + Spring kaynak/hedef modelleri (Java ile aynı modeller).
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class Api {
    @GetMapping("/cmd")
    fun cmd(@RequestParam host: String, count: Int): String {
        Runtime.getRuntime().exec("ping " + host) // EXPECT: command
        Runtime.getRuntime().exec("ping -c " + count)
        return "ok"
    }

    @GetMapping("/file")
    fun file(name: String): String {
        java.io.FileInputStream("/data/" + name) // EXPECT: path
        java.io.FileInputStream("/data/sabit")
        return "ok"
    }
}
