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

import javax.servlet.ServletContext;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.Resources;

@Provider
@PreMatching
public class APIAuthFilter implements ContainerRequestFilter{
	private static final String API_KEY = "X-API-KEY";
	private static final Logger LOG = LoggerFactory.getLogger(APIAuthFilter.class);

	@Context
	private ServletContext request;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {

		UriInfo info = requestContext.getUriInfo();

		//only protect paths with /api
		if (!info.getPath().contains("api/")) {
			return;
		}

		String apiKey = requestContext.getHeaders().getFirst(API_KEY);
		Configuration config = Resources.getConfiguration(request);


		//do nothing if no api key is set
		if (config.getAPIKey()==null || config.getAPIKey().isEmpty()) {
			return;
		}


		if (apiKey == null ||  
				apiKey.isEmpty() || !apiKey.equals(config.getAPIKey())) {  
			requestContext  
			.abortWith(  
					Response  
					.status(Response.Status.UNAUTHORIZED)  
					.entity("Please provide a valid API Key")  
					.build());  
		}  

		LOG.debug("API key sent: "+apiKey);

	}  

}
