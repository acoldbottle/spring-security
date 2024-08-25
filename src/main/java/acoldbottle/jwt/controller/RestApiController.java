package acoldbottle.jwt.controller;

import acoldbottle.jwt.domain.User;
import acoldbottle.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @GetMapping("/admin/users")
    public List<User> users() {
        return userRepository.findAll();
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("USER");
        userRepository.save(user);
        return "회원가입 완료";
    }

    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
