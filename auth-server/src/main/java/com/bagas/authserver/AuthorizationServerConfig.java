package com.bagas.authserver;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	
	// boilerplate
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerFilterChain(HttpSecurity http) throws
	Exception{
		OAuth2AuthorizationServerConfiguration
			.applyDefaultSecurity(http);
		
		return http
				.formLogin(Customizer.withDefaults())
				.build();
	}
	/*
	 Client ID—Analogous to a username, but instead of a user, it is a client. In this
case, "taco-admin-client"
	 Client secret—Analogous to a password for the client. Here we’re using the word
"secret" for the client secret.
	 Authorization grant type—The OAuth 2 grant types that this client will support.
In this case, we’re enabling authorization code and refresh token grants.
	 Redirect URL—One or more registered URLs that the authorization server can
redirect to after authorization has been granted. This adds another level of
security, preventing some arbitrary application from receiving an authorization
code that it could exchange for a token
	Scope—One or more OAuth 2 scopes that this client is allowed to ask for. Here
we are setting three scopes: "writeIngredients", "deleteIngredients", and
the constant OidcScopes.OPENID, which resolves to "openid".
	Client settings—This is a lambda that allows us to customize the client settings.
In this case, we’re requiring explicit user consent before granting the
requested scope. Without this, the scope would be implicitly granted after the
user logs in
	 * */
	@Bean
	public RegisteredClientRepository registeredClientRepository(
			PasswordEncoder passwordEncoder)
	{
		
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("taco-admin-client")
				.clientSecret(passwordEncoder.encode("secret"))
				.clientAuthenticationMethod(
						ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1.9090/login/oauth2/code/taco-admin-client")
				.scope("writeIngredients")
				.scope("deleteIngredients")
				.scope(OidcScopes.OPENID)
				.clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
				.build();
		return new InMemoryRegisteredClientRepository(registeredClient);
		
		
	
		
		
	}
	
	
	
	
	
	
	
}
