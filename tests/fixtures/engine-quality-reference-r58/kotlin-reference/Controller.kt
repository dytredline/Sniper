@RestController
class JobsController {
    @GetMapping("/run")
    fun run(@RequestParam command: String) {
        val action = ::dangerous
        action(command)
    }
    fun dangerous(value: String) { Runtime.getRuntime().exec(value) }
}
