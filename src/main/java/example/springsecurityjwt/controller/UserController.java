package example.springsecurityjwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/user")
    public ResponseEntity<?> getUser() {
        return ResponseEntity.ok().body("Hi user");
    }

    @GetMapping("/admin")
    public ResponseEntity<?> getAdmin() {
        return ResponseEntity.ok().body("Hi admin");
    }
}
