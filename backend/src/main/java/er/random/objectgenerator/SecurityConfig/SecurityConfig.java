package er.random.objectgenerator.SecurityConfig;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@Configuration
//@EnableOAuth2Sso      // one server for one frontend
//@EnableOAuth2Client   // one server for one frontend
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  public static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization_code";

  @Override
  public void configure(HttpSecurity http) throws Exception {
    http                        // @formatter:off
        .authorizeRequests()
        .antMatchers("/", "/index", "/logout").permitAll()
        .anyRequest().authenticated()
        .and()
        .oauth2Login()
        .loginPage("/")
        .authorizationEndpoint()
        .baseUri(AUTHORIZATION_REQUEST_BASE_URI)
        .authorizationRequestRepository(authorizationRequestRepository())
        .and()
        .redirectionEndpoint()
        .baseUri("/oauth2/callback/*")
        .and()
        .tokenEndpoint()
        .accessTokenResponseClient(accessTokenResponseClient())
    ;                           // @formatter:on
  }

  @Bean
  public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
    return new HttpSessionOAuth2AuthorizationRequestRepository();
  }

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
    return new DefaultAuthorizationCodeTokenResponseClient();
  }

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/resources/**", "/static/**", "/images/**", "/css/**", "/js/**", "**/favicon**", "**/index.html");
  }
}