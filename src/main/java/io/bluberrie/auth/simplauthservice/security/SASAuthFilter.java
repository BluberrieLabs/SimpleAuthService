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

import java.io.IOException;

import javax.annotation.Priority;
import javax.servlet.ServletContext;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



@Provider
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class SASAuthFilter implements ContainerRequestFilter {

	private static final Logger LOG = LoggerFactory.getLogger(SASAuthFilter.class);
	@Context
	private ServletContext request;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {

		try {
			SASSecurityContext asc = new SASSecurityContext(requestContext, request);

			requestContext.setSecurityContext(asc);

		} catch (InvalidCredential e) {

			LOG.error("User not authenticated");
		}

	}

}
