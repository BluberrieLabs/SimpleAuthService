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

import javax.annotation.security.RolesAllowed;
import javax.persistence.Query;
import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.Response.Status;

import org.hibernate.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.Resources;
import io.bluberrie.auth.simplauthservice.Util;
import io.bluberrie.auth.simplauthservice.blobs.LoginData;
import io.bluberrie.auth.simplauthservice.blobs.MessageData;
import io.bluberrie.auth.simplauthservice.blobs.TokenData;
import io.bluberrie.auth.simplauthservice.persist.SimpleRefreshToken;
import io.bluberrie.auth.simplauthservice.persist.SimpleUser;
import io.bluberrie.auth.simplauthservice.security.Roles;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;

@Path("api/me")
@Api(value = "api/me", authorizations = {
		@Authorization(value = "api_key"), @Authorization(value = "bearer")}
		)
public class Me {

	private static final Logger LOG = LoggerFactory.getLogger(Auth.class);

	private Configuration config;

	public Me(@Context ServletContext ctx, @Context HttpHeaders headers) {
		config = Resources.getConfiguration(ctx);
	}

	// Log out
	@POST
	@RolesAllowed(Roles.REFRESH)
	@Path("logout")
	@ApiOperation(value = "Do user logout",
	notes = "Withdraws refresh token based on presented refresh tokenid",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User logged out"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON)
	public Response logOut(@Context SecurityContext sc) {

		// remove refresh credential from list
		// credential id set to user

		try {
			String jti = sc.getUserPrincipal().getName();

			Session session = config.getSession();
			session.beginTransaction();
			String hql = "DELETE FROM SimpleRefreshToken " + "WHERE tokenid = :tokenid";
			Query query = session.createQuery(hql);
			query.setParameter("tokenid", jti);

			query.executeUpdate();
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(new MessageData("user logged out")).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}

	// Renew cred
	@GET
	@RolesAllowed(Roles.REFRESH)
	@Path("newcred")
	@ApiOperation(value = "Refresh token",
	notes = "Renews JWT token based on presented refresh tokenid",
	response = TokenData.class
			)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Token refreshed"),
			@ApiResponse(code = 403, message = "User account locked"),
			@ApiResponse(code = 404, message = "Unknown refresh token"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON)
	public Response newCred(@Context SecurityContext sc) {

		try {
			String jti = sc.getUserPrincipal().getName();

			Session session = config.getSession();

			SimpleRefreshToken srt = session
					.createQuery("from SimpleRefreshToken where tokenid='" + jti + "'", SimpleRefreshToken.class)
					.uniqueResult();

			if (srt == null) {
				return Util.getError("Unknown refresh token", Status.NOT_FOUND);

			}

			SimpleUser usr = srt.getUser();
			// TODO: Check lock
			if (Util.checkAccountLock(usr)) {
				session.close();
				return Util.getError("User account locked", Status.FORBIDDEN);

			}

			usr.setLast_login(new Date());

			session.beginTransaction();
			session.update(usr);
			session.getTransaction().commit();
			session.close();


			return Response.ok().entity(new TokenData(usr.getJWT(config), null)).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);

			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);

		}
	}

	// Renew refresh token
	@GET
	@RolesAllowed(Roles.REFRESH)
	@Path("exchange")
	@ApiOperation(value = "Renew refresh token",
	notes = "Renews refresh token based on presented refresh tokenid",
	response = TokenData.class 
			)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Token refreshed"),
			@ApiResponse(code = 403, message = "User account locked"),
			@ApiResponse(code = 404, message = "Unknown refresh token"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON)
	public Response refresh(@Context SecurityContext sc) {

		try {
			String jti = sc.getUserPrincipal().getName();

			Session session = config.getSession();
			session.beginTransaction();

			SimpleRefreshToken srt = session
					.createQuery("from SimpleRefreshToken where tokenid='" + jti + "'", SimpleRefreshToken.class)
					.uniqueResult();

			if (srt == null) {
				return Util.getError("Unknown refresh token", Status.NOT_FOUND);

			}

			SimpleUser usr = srt.getUser();
			// TODO: Check lock
			if (Util.checkAccountLock(usr)) {
				session.close();
				return Util.getError("User account locked", Status.FORBIDDEN);
			}

			String hql = "DELETE FROM SimpleRefreshToken " + "WHERE tokenid = :tokenid";
			Query query = session.createQuery(hql);
			query.setParameter("tokenid", jti);

			query.executeUpdate();

			String refreshToken = usr.getRefreshJWT(config);

			session.update(usr);
			session.getTransaction().commit();
			session.close();


			return Response.ok().entity(new TokenData(null, refreshToken)).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);

			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);

		}

	}

	// TODO: Delete account
	@DELETE
	@RolesAllowed(Roles.USER)
	@Path("delete")
	@ApiOperation(value = "Delete user account",
	notes = "Deletes user based on presented refresh tokenid",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Used deleted"),
			@ApiResponse(code = 500, message = "Error deleting user")})
	@Produces(MediaType.APPLICATION_JSON)
	public Response deleteAccount(@Context SecurityContext sc) {

		try {
			String user = sc.getUserPrincipal().getName();

			Session session = config.getSession();
			session.beginTransaction();
			// TODO: Check lock

			String hql = "DELETE FROM SimpleUser " + "WHERE uuid = :uuid";
			Query query = session.createQuery(hql);
			query.setParameter("uuid", user);

			query.executeUpdate();
			session.getTransaction().commit();

			session.close();
			return Response.ok().entity(new MessageData("user deleted")).build();

		} catch (Exception e) {
			LOG.error("Error deleting user", e);
			return Util.getError("Error deleting user", Status.INTERNAL_SERVER_ERROR);
		}

	}

	// close account
	@POST
	@RolesAllowed(Roles.USER)
	@Path("close")
	@ApiOperation(value = "Close user account",
	notes = "Closes user account based on presented refresh tokenid",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Account closed"),
			@ApiResponse(code = 500, message = "Error closing account")})
	@Produces(MediaType.APPLICATION_JSON)
	public Response closeAccount(@Context SecurityContext sc) {

		try {
			String user = sc.getUserPrincipal().getName();

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "UPDATE SimpleUser set isClosed = :closed WHERE uuid = :uuid";
			Query query = session.createQuery(hql);

			query.setParameter("uuid", user);
			query.setParameter("closed", true);

			query.executeUpdate();
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(new MessageData("account closed")).build();

		} catch (Exception e) {
			LOG.error("Error closing account", e);
			return Util.getError("Error closing account", Status.INTERNAL_SERVER_ERROR);
		}

	}

	// reopen account
	@POST
	@RolesAllowed(Roles.USER)
	@Path("reopen")
	@ApiOperation(value = "Reopen user account",
	notes = "Reopens user account based on presented refresh tokenid",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Account reopened"),
			@ApiResponse(code = 500, message = "Error reopening account")})
	@Produces(MediaType.APPLICATION_JSON)
	public Response reopenAccount(@Context SecurityContext sc) {

		try {
			String user = sc.getUserPrincipal().getName();

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "UPDATE SimpleUser set isClosed = :closed WHERE uuid = :uuid";
			Query query = session.createQuery(hql);

			query.setParameter("uuid", user);
			query.setParameter("closed", false);

			query.executeUpdate();
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(new MessageData("account reopened")).build();

		} catch (Exception e) {
			LOG.error("Error reopening account", e);
			return Util.getError("Error reopening account", Status.INTERNAL_SERVER_ERROR);
		}

	}

	// TODO: Change password
	@POST
	@RolesAllowed(Roles.USER)
	@Path("update")
	@ApiOperation(value = "Update user account",
	notes = "Updates account with supplied details based on presented refresh tokenid",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Account reopened"),
			@ApiResponse(code = 403, message = "User account locked"),
			@ApiResponse(code = 500, message = "Error updating account")})
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response changeDetails(LoginData login, @Context SecurityContext sc) {

		try {

			String user = sc.getUserPrincipal().getName();

			Session session = config.getSession();

			SimpleUser usr = (SimpleUser) session.createQuery("from SimpleUser where uuid='" + user + "'")
					.uniqueResult();

			// TODO: Check lock
			if (Util.checkAccountLock(usr)) {
				session.close();
				return Util.getError("User account locked", Status.FORBIDDEN);
			}

			if (login.email != null && !login.email.isEmpty()) {
				usr.setEmail(login.email);
			}

			if (login.name != null && !login.name.isEmpty()) {
				usr.setFullname(login.name);
			}

			if (login.password != null && !login.password.isEmpty()) {
				usr.setPassword(login.password);
			}

			session.beginTransaction();
			session.update(usr);
			session.getTransaction().commit();
			session.close();

			return Response.ok().entity(new MessageData("account updated")).build();
		} catch (Exception e) {
			LOG.error("Error updating account", e);
			return Util.getError("Error updating account", Status.INTERNAL_SERVER_ERROR);

		}
	}
}
