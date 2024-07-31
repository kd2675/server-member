package com.example.member.service.oauth2.act;

import com.example.member.common.config.jwt.provider.JwtTokenProvider;
import com.example.member.service.auth.api.dto.LoginParamDTO;
import com.example.member.service.auth.api.dto.TokenDTO;
import com.example.member.service.oauth2.biz.Oauth2Service;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.core.response.base.dto.ResponseDTO;
import org.example.core.response.base.dto.ResponseDataDTO;
import org.example.core.response.base.vo.Code;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Controller
@RequestMapping(value = "/oauth2")
public class OAuth2Controller {
    private final Oauth2Service oauth2Service;
    private final JwtTokenProvider jwtTokenProvider;

    //(GET)/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fc
    //[출처] OAuth 2.0 동작 방식의 이해|작성자 MDS인텔리전스

    @GetMapping("/authorize")
    public String Authorize(
            Model model,
            @RequestParam(value = "response_type") String responseType,
            @RequestParam(value = "client_id") String clientId,
            @RequestParam(value = "state") String state,
            @RequestParam(value = "redirect_url") String redirectUrl
    ) {
        model.addAttribute("responseType", responseType);
        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("redirectUrl", redirectUrl);
        return "/index";
    }

    @ResponseBody
    @PostMapping("/authorize")
    public ResponseDTO loginToAuthorize(@Valid @RequestBody LoginParamDTO loginParamDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseDataDTO.of(false, Code.VALIDATION_ERROR, bindingResult.getFieldErrors().stream().map(v -> v.getField()).collect(Collectors.joining(",")));
        }
        return ResponseDataDTO.of(oauth2Service.loginToAuthorizationCode(loginParamDTO));
    }

    @ResponseBody
    @PostMapping("/token")
    public ResponseDataDTO<TokenDTO> token(@RequestHeader("Authorization") String authorizationCode) {
        TokenDTO tokenDTO = oauth2Service.authorizationCodeToken(authorizationCode);
        return ResponseDataDTO.of(tokenDTO);
    }
}
