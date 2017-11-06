/*
 * (C) Copyright 2017 Bluberrie Labs (http://bluberrie.io/).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.bluberrie.auth.simplauthservice.security;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletContext;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;

import org.hibernate.Hibernate;
import org.hibernate.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.Resources;
import io.bluberrie.auth.simplauthservice.persist.SimpleRefreshToken;
import io.bluberrie.auth.simplauthservice.persist.SimpleUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class SASSecurityContext implements SecurityContext {
	private static final Logger LOG = LoggerFactory.getLogger(SASSecurityContext.class);
	private final boolean secure;
	private static final String AUTHENTICATION_SCHEME = "Bearer";
	private List<String> roles = null;
	private String user = null;

	public SASSecurityContext(ContainerRequestContext reqCtx, ServletContext request) throws InvalidCredential {
		this.secure = true;
		// this.secure = reqCtx.getSecurityContext().isSecure();		

		String authorizationHeader = reqCtx.getHeaderString(HttpHeaders.AUTHORIZATION);

		// Check if the HTTP Authorization header is present and formatted
		// correctly
		if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
			LOG.info("Auth header not provided");
			throw new InvalidCredential("Authorization header must be provided");
		}

		// Extract the token from the HTTP Authorization header
		String token = authorizationHeader.substring("Bearer".length()).trim();

		LOG.debug("Got header: "+token);

		Configuration config = Resources.getConfiguration(request);

		// Check JWT
		try {

			Jws<Claims> tok = Jwts.parser().setSigningKey(config.getJWTPublicKey()).parseClaimsJws(token);


			if (tok.getBody().containsKey("jti")) {
				//this is a refresh token

				//check audience
				if (!tok.getBody().getAudience().equals(config.getRefreshAudience())) {
					LOG.info("Invalid audience in refresh credential");
					throw new InvalidCredential("Invalid refresh credential");
				}

				//check jti is in database
				String jti = (String)tok.getBody().get("jti");
				String u =tok.getBody().getSubject();

				Session session = config.getSession();
				session.beginTransaction();

				SimpleUser usr = session.createQuery("from SimpleUser where uuid='"+u+"'", SimpleUser.class).uniqueResult();

				Hibernate.initialize(usr.getRefreshTokens());

				session.close();

				boolean valid = false;

				for (SimpleRefreshToken t: usr.getRefreshTokens()) {

					if (t.getTokenid().equals(jti)) {
						valid=true;
						break;
					}

				}

				if (!valid) {
					LOG.info("Invalid refresh credential supplied");
					throw new InvalidCredential("Invalid refresh credential");
				}

				roles=new ArrayList<String>();

				//this token can only be used to refresh other tokens, hence just has the REFRESH role
				roles.add(Roles.REFRESH);

				user=jti;

			} else {

				user =tok.getBody().getSubject();

				LOG.debug("Got token for "+user+" expires "+tok.getBody().getExpiration().toString());

				String roleattrib = (String) tok.getBody().get("scopes");

				if (roleattrib != null) {

					roles=Arrays.asList(roleattrib.split(":"));

				}

			}

			//OK, we can trust this JWT

		} catch (JwtException e) {

			LOG.error("Problem parsing token: ", e);

			//don't trust the JWT!
		}

	}

	@Override
	public String getAuthenticationScheme() {
		return AUTHENTICATION_SCHEME;
	}

	@Override
	public Principal getUserPrincipal() {

		if (user == null) {
			LOG.debug("User is null");
			return null;
		}

		return new Principal() {
			@Override
			public String getName() {
				return user;
			}

		};

	}

	@Override
	public boolean isSecure() {
		return secure;
	}

	@Override
	public boolean isUserInRole(String role) {

		if (roles==null) {
			return false;
		}

		return roles.contains(role);
	}

}
