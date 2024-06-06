package cquizs.auth.controller;

import cquizs.auth.dto.UserData.Join;
import cquizs.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class JoinController {

    private final UserService userService;

    @PostMapping("/join")
    public String join(Join join) {
        userService.join(join);

        return "ok";
    }
}
