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
package io.bluberrie.auth.simplauthservice;

import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import io.swagger.annotations.ApiKeyAuthDefinition;
import io.swagger.annotations.ApiKeyAuthDefinition.ApiKeyLocation;
import io.swagger.annotations.OAuth2Definition;
import io.swagger.annotations.Scope;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.jaxrs.config.BeanConfig;
import io.swagger.annotations.SecurityDefinition;


@SwaggerDefinition(
		securityDefinition = @SecurityDefinition(
				apiKeyAuthDefinitions={@ApiKeyAuthDefinition(name="x-api-key", in = ApiKeyLocation.HEADER, key = "api_key"), @ApiKeyAuthDefinition(name="Authorization", in = ApiKeyLocation.HEADER, key = "bearer")}
				)
		)
public class SimpleAuth extends ResourceConfig {

	public SimpleAuth() {
		packages("io.bluberrie.auth.simplauthservice");	//set the package name
		register(RolesAllowedDynamicFeature.class); //allow role annotation to work
		
		//for Swagger
        register(io.swagger.jaxrs.listing.ApiListingResource.class);
        register(io.swagger.jaxrs.listing.SwaggerSerializers.class);
        
        BeanConfig beanConfig = new BeanConfig();
        beanConfig.setDescription("A simple API to manage user authentication");
        beanConfig.setVersion("1.0.0");
        beanConfig.setTitle("SimpleAuthenticationService");
        beanConfig.setSchemes(new String[]{"http", "https"});
        beanConfig.setHost("localhost:8080");
        beanConfig.setBasePath("/sas/v1");
        beanConfig.setResourcePackage("io.bluberrie.auth.simplauthservice");
        beanConfig.setScan(true);
        beanConfig.setPrettyPrint(true);
        
        
        
	}
}