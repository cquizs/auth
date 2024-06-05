package cquizs.auth.controller;

import cquizs.auth.dto.JoinDto;
import cquizs.auth.service.JoinService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Slf4j
@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @GetMapping("/join")
    public String mvJoin() {
        return "join";
    }

    @PostMapping("/join")
    public String join(JoinDto joinDto){
        log.debug("{}", joinDto);
        joinService.join(joinDto);

        return "redirect:/login";
    }
}
