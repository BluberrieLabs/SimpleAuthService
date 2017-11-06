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
package io.bluberrie.auth.simplauthservice.endpoints;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.ServletContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.hibernate.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.Resources;
import io.bluberrie.auth.simplauthservice.Util;
import io.bluberrie.auth.simplauthservice.blobs.TotalData;
import io.bluberrie.auth.simplauthservice.mail.MailTriggers;
import io.bluberrie.auth.simplauthservice.persist.SimpleUser;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;


/**
 * A set of public facing utility services that require no authentication or API key
 *
 */
@Path("service")
@Api(value = "service")
public class Open {

	private Configuration config;

	private static final Logger LOG = LoggerFactory.getLogger(Open.class);

	public Open(@Context ServletContext ctx, @Context HttpHeaders headers) {
		config=Resources.getConfiguration(ctx);
	}


	/**
	 * Get the public certificate used to sign JWT requests
	 *
	 * @return The X.509 formatted certificate
	 */
	@GET
	@Path("cert")
	@ApiOperation(value = "Get the public JWT certificate",
	notes = "Returns the X.509 cert used to sign JWT tokens",
	response = String.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "The X.509 certificate"),
			@ApiResponse(code = 404, message = "Certificate not available")})
	@Produces(MediaType.TEXT_PLAIN) 
	public Response getCert() {

		String contents;
		try {
			contents = new String(Files.readAllBytes(Paths.get(config.getPublicKeyFile())));
			return Response.ok(contents).build();

		} catch (IOException e) {
			return Util.getError("No certificate available", Status.NO_CONTENT);
		}


	}


	/**
	 * Confirms the users email address
	 *
	 */	
	@GET
	@Path("confirm/{id}")
	@ApiOperation(value = "Confirm the user email address",
	notes = "Redirects to the specified confirmation page",
	response = String.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 303, message = "redirect to the confirmation page"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.TEXT_HTML) 
	public Response confirmEmail(@ApiParam(value = "user id", required = true) @PathParam("id") String id) {


		try {

			Session session = config.getSession();
			session.beginTransaction();

			SimpleUser usr = session.createQuery("from SimpleUser where uuid='"+id+"'", SimpleUser.class).uniqueResult();

			if (!usr.isEmailConfirmed()) {

				usr.setEmailConfirmed(true);

				session.update(usr);
				session.getTransaction().commit();
				session.close();

				config.getMailSender().sendMessage(MailTriggers.WELCOME, usr.getEmail(), usr.getFullname());

			}

			return Response.seeOther(new URI(config.getConfirmRedirect())).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}


	}


}
