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

import java.util.Date;
import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.hibernate.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.DispatchException;
import io.bluberrie.auth.simplauthservice.Resources;
import io.bluberrie.auth.simplauthservice.Util;
import io.bluberrie.auth.simplauthservice.blobs.FBToken;
import io.bluberrie.auth.simplauthservice.blobs.LoginData;
import io.bluberrie.auth.simplauthservice.blobs.MessageData;
import io.bluberrie.auth.simplauthservice.blobs.TokenData;
import io.bluberrie.auth.simplauthservice.mail.MailTriggers;
import io.bluberrie.auth.simplauthservice.persist.SimpleUser;
import io.bluberrie.auth.simplauthservice.security.FacebookAuth;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiKeyAuthDefinition;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ApiKeyAuthDefinition.ApiKeyLocation;

@Path("api/auth")
@Api(value = "api/auth", authorizations = {
		@Authorization(value = "api_key")}
)

@Produces({"application/json"})
public class Auth {
	private static final Logger LOG = LoggerFactory.getLogger(Auth.class);

	private Configuration config;

	public Auth(@Context ServletContext ctx, @Context HttpHeaders headers) {
		config=Resources.getConfiguration(ctx);
	}

	@POST
	@Path("create")
	@ApiOperation(value = "Create a new user with username & password",
	notes = "Return a JWT token for the user and a refresh token",
	response = TokenData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User created"),
			@ApiResponse(code = 406, message = "User details invalid"),
			@ApiResponse(code = 409, message = "User doesn't exist"),
			@ApiResponse(code = 500, message = "Error validating user")})
	@Consumes(MediaType.APPLICATION_JSON) 
	@Produces(MediaType.APPLICATION_JSON) 
	public Response createUser(LoginData login) {

		//check paramters
		if (login.name==null || login.password==null || login.email==null) {

			return Util.getError("Name, password or email missing", Status.NOT_ACCEPTABLE);	
		}

		Session session = config.getSession();

		//check if user exists
		SimpleUser usr = (SimpleUser)session.createQuery("from SimpleUser where email='"+login.getEmail()+"'").uniqueResult();

		if (usr != null) {
			session.close();
			return Util.getError("User exists", Status.CONFLICT);
		}

		try {
			SimpleUser newuser = new SimpleUser(login.name, login.password, login.email);

			String refreshToken=newuser.getRefreshJWT(config);

			session.beginTransaction();
			session.save(newuser);
			session.getTransaction().commit();

			session.close();


			String url = config.getServerURL()+"/sas/service/confirm/"+newuser.getUuid();

			config.getMailSender().sendMessage(MailTriggers.EMAILCONF, login.email, login.name, url);

			return Response.ok().entity(new TokenData(newuser.getJWT(config), refreshToken)).build();
		} catch (Exception e) {
			LOG.error("Error creating user", e);
			return Util.getError("Error creating user", Status.INTERNAL_SERVER_ERROR);
		}

	}




	@POST
	@Path("auth")
	@ApiOperation(value = "Authorize an existing user with username & password",
	notes = "Return a JWT token for the user and optionally a refresh token if web=false",
	response = TokenData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Token sent"),
			@ApiResponse(code = 403, message = "User details invalid"),
			@ApiResponse(code = 404, message = "User doesn't exist"),
			@ApiResponse(code = 500, message = "Error validating user")})
	@Consumes(MediaType.APPLICATION_JSON) 
	@Produces(MediaType.APPLICATION_JSON) 
	public Response doLogin (LoginData login, @ApiParam(value = "web request", required = false) @DefaultValue("false") @QueryParam("web") boolean isWeb) {

		try { 


			Session session = config.getSession();

			//check if user exists
			SimpleUser usr = session.createQuery("from SimpleUser where email='"+login.getEmail()+"'" , SimpleUser.class).uniqueResult();

			if (usr == null) {
				session.close();
				return Util.getError("User doesn't exist", Status.NOT_FOUND);
			}

			if (usr.validatePassword(login.getPassword())) {

				//create the JWT


				if (Util.checkAccountLock(usr)) {
					session.close();
					return Util.getError("User account locked", Status.FORBIDDEN);

				}


				usr.setLast_login(new Date());

				String refreshToken = null;
				if (!isWeb) {
					refreshToken=usr.getRefreshJWT(config);
				}

				session.beginTransaction();
				session.update(usr);
				session.getTransaction().commit();
				session.close();

				String token;
				if (isWeb) {
					token = usr.getJWT(config, config.getWebTokenLife());
				} else {
					token=usr.getJWT(config);
				}

				return Response.ok().entity(new TokenData(token, refreshToken)).build(); 
			} else {
				return Util.getError("Login details incorrect", Status.FORBIDDEN);
			}
		} catch (Exception e) {
			LOG.error("Error validating user", e);
			return Util.getError("Error validating user", Status.INTERNAL_SERVER_ERROR);
		}
	}

	//Reset password
	@GET
	@Path("forgotpwd")
	@ApiOperation(value = "Request a password reset email",
	notes = "Reset email sent for specified address",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Reset email sent"),
			@ApiResponse(code = 404, message = "User doesn't exist"),
			@ApiResponse(code = 500, message = "Error validating user")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response resetPasswd (@ApiParam(value = "user email", required = true) @QueryParam("email") String email) {

		try { 
			//get user based on email
			Session session = config.getSession();

			//check if user exists
			SimpleUser usr = session.createQuery("from SimpleUser where email='"+email+"'" , SimpleUser.class).uniqueResult();

			if (usr == null) {
				session.close();
				return Util.getError("User doesn't exist", Status.NOT_FOUND);
			}

			//generate & save reset token
			String resetToken=Util.nextSessionId();
			Date resetTokenExpires = new Date(System.currentTimeMillis() + config.getResetTokenLife());

			usr.setResetToken(resetToken);
			usr.setResetTokenExpires(resetTokenExpires);

			session.beginTransaction();
			session.update(usr);
			session.getTransaction().commit();
			session.close();

			String url = config.getResetURL()+"?tk="+resetToken+"&email="+usr.getEmail();

			config.getMailSender().sendMessage(MailTriggers.RESET, usr.getEmail(), usr.getFullname(), url);

			return Response.ok().entity(new MessageData("Reset email sent")).build();

		} catch (Exception e) {
			LOG.error("Error validating user", e);
			return Util.getError("Error validating user", Status.INTERNAL_SERVER_ERROR);
		}

	}

	@POST
	@Path("resetpwd/{resettoken}")
	@ApiOperation(value = "Reset user's password",
	notes = "Resets the user's password. Requires the valid reset token to be supplied",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Password reset"),
			@ApiResponse(code = 404, message = "User doesn't exist"),
			@ApiResponse(code = 500, message = "Error validating user")})
	@Consumes(MediaType.APPLICATION_JSON) 
	@Produces(MediaType.APPLICATION_JSON) 
	public Response resetPWD(LoginData login, @ApiParam(value = "reset token", required = true) @PathParam("resettoken") String resettoken) {

		try { 

			Session session = config.getSession();

			//check if user exists
			SimpleUser usr = session.createQuery("from SimpleUser where email='"+login.getEmail()+"'" , SimpleUser.class).uniqueResult();

			if (usr == null) {
				session.close();
				return Util.getError("User doesn't exist", Status.NOT_FOUND);
			}

			if (usr.getResetToken() == null || !usr.getResetToken().equals(resettoken)) {
				session.close();
				return Util.getError("Invalid token", Status.NOT_FOUND);
			}

			//check if token has expired
			if (usr.getResetTokenExpires() == null || usr.getResetTokenExpires().before(new Date())) {
				session.close();
				return Util.getError("Token expired", Status.NOT_FOUND);
			}

			if (login.password != null && !login.password.isEmpty()) {
				usr.setPassword(login.password);
				usr.setResetToken("");
				//usr.setResetTokenExpires(null);
			}

			session.beginTransaction();
			session.update(usr);
			session.getTransaction().commit();
			session.close();

			return Response.ok().entity(new MessageData("Password reset")).build();

		} catch (Exception e) {
			LOG.error("Error resetting password", e);
			return Util.getError("Error resetting password", Status.INTERNAL_SERVER_ERROR);
		}

	}

	//TODO: FB login
	@POST
	@Path("facebooklogin")
	@ApiOperation(value = "Authorize an existing user with a Facebook credential",
	notes = "Return a JWT token for the user and a refresh token",
	response = TokenData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Token sent"),
			@ApiResponse(code = 403, message = "User forbidden"),
			@ApiResponse(code = 500, message = "Error validating user")})
	@Consumes(MediaType.APPLICATION_JSON) 	@Produces(MediaType.APPLICATION_JSON) 
	public Response fbLogin (FBToken fbtoken, @ApiParam(value = "web request", required = false) @DefaultValue("false") @QueryParam("web") boolean isWeb) {

		FacebookAuth fbauth = new FacebookAuth(config);

		try {
			SimpleUser su=fbauth.authWithFacebook(fbtoken.getFbtoken());

			//TODO: Check lock
			if (Util.checkAccountLock(su)) {
				return Util.getError("User account locked", Status.FORBIDDEN);

			}


			String refreshToken=null;
			if (!isWeb) {
				refreshToken=su.getRefreshJWT(config);
			}
			Session session = config.getSession();
			session.beginTransaction();
			session.update(su);
			session.getTransaction().commit();
			session.close();


			return Response.ok(new TokenData(su.getJWT(config), refreshToken)).build();

		} catch (DispatchException e) {
			LOG.error("Error authenticating with facebook", e);

			return Util.getError("Error authenticating with facebook", Status.INTERNAL_SERVER_ERROR);

		}

	}


}

