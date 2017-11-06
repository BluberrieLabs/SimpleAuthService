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

import java.util.ArrayList;
import java.util.List;

import javax.annotation.security.RolesAllowed;
import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.hibernate.Session;
import org.hibernate.query.Query;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.Resources;
import io.bluberrie.auth.simplauthservice.Util;
import io.bluberrie.auth.simplauthservice.blobs.MessageData;
import io.bluberrie.auth.simplauthservice.blobs.TokenData;
import io.bluberrie.auth.simplauthservice.blobs.TotalData;
import io.bluberrie.auth.simplauthservice.blobs.UserData;
import io.bluberrie.auth.simplauthservice.mail.MailTriggers;
import io.bluberrie.auth.simplauthservice.persist.SimpleEmail;
import io.bluberrie.auth.simplauthservice.persist.SimpleUser;
import io.bluberrie.auth.simplauthservice.security.Roles;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.AuthorizationScope;

@Path("api/admin")
@Api(value = "api/admin", authorizations = {
		@Authorization(value = "api_key"), @Authorization(value = "bearer")}
		)
public class Admin {

	private static final Logger LOG = LoggerFactory.getLogger(Admin.class);

	private Configuration config;

	public Admin(@Context ServletContext ctx, @Context HttpHeaders headers) {
		config=Resources.getConfiguration(ctx);
	}

	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("totalusers")
	@ApiOperation(value = "Get the total number of users",
	notes = "Returns the number of user records",
	response = TotalData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User number"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response getUserTotal() {

		try {
			Session session=config.getSession();

			String countQ = "Select count (uuid) from SimpleUser";
			Long total = session.createQuery(countQ, Long.class).uniqueResult();

			session.close();

			return Response.ok().entity(new TotalData(total)).build();
		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}
	}

	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("users")
	@ApiOperation(value = "Get all users",
	notes = "Returns a listing of all user details",
	response = UserData.class, 
	responseContainer = "List")
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User records"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response getAllUsers() {

		try {
			Session session=config.getSession();

			Query<SimpleUser> query = session.createQuery("from SimpleUser", SimpleUser.class);

			List<SimpleUser> userList = query.list();

			List<UserData> reply = new ArrayList<UserData>();

			for (SimpleUser usr: userList) {
				reply.add(usr.getAdminUserData());
			}

			session.close();


			return Response.ok().entity(reply).build();
		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}
	}

	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("users/{first}/{max}")
	@ApiOperation(value = "Get first to max users",
	notes = "Returns a listing of all specified user details",
	response = UserData.class, 
	responseContainer = "List")
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User records"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response getUsers(@ApiParam(value = "first record", required = true) @PathParam("first") int first, @ApiParam(value = "last record", required = true) @PathParam("max") int max) {

		try {
			Session session=config.getSession();

			Query<SimpleUser> query = session.createQuery("from SimpleUser", SimpleUser.class);
			query.setFirstResult(first);
			query.setMaxResults(max);


			List<SimpleUser> userList = query.list();

			List<UserData> reply = new ArrayList<UserData>();

			for (SimpleUser usr: userList) {
				reply.add(usr.getAdminUserData());
			}

			session.close();


			return Response.ok().entity(reply).build();
		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}
	}


	// TODO: Get user
	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}")
	@ApiOperation(value = "Get a specific user",
	notes = "Returns the specified user details",
	response = UserData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User record"),
			@ApiResponse(code = 409, message = "User doesn't exist"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON)
	public Response getUser(@ApiParam(value = "user id", required = true) @PathParam("id") String id) {

		try {

			Session session = config.getSession();

			SimpleUser usr = session.createQuery("from SimpleUser where uuid='"+id+"'", SimpleUser.class).uniqueResult();

			if (usr == null) {
				session.close();
				return Util.getError("User doesn't exist", Status.NO_CONTENT);
			}

			session.close();

			return Response.ok().entity(usr.getAdminUserData()).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);

			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);

		}
	}


	//add role
	@POST
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}/{role}")
	@ApiOperation(value = "Add a specific role to a specific user",
	notes = "Returns the specified user details",
	response = UserData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User record"),
			@ApiResponse(code = 409, message = "User doesn't exist"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response addRole(@ApiParam(value = "user id", required = true) @PathParam("id") String id, 
			@ApiParam(value = "role to add", required = true) @PathParam("role") String role) {
		try {

			Session session = config.getSession();

			SimpleUser usr = session.createQuery("from SimpleUser where email='"+id+"'", SimpleUser.class).uniqueResult();

			if (usr == null) {
				session.close();
				return Util.getError("User doesn\t exist", Status.NO_CONTENT);
			}

			usr.addRole(role);

			session.beginTransaction();
			session.saveOrUpdate(usr);
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(usr.getAdminUserData()).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);

			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);

		}

	}

	//add role
	@DELETE
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}/{role}")
	@ApiOperation(value = "Remove a specific role from a specific user",
	notes = "Returns the specified user details",
	response = UserData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User record"),
			@ApiResponse(code = 409, message = "User doesn't exist"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response removeRole(@ApiParam(value = "user id", required = true) @PathParam("id") String id, 
			@ApiParam(value = "role to add", required = true) @PathParam("role") String role) {
		try {

			Session session = config.getSession();

			SimpleUser usr = session.createQuery("from SimpleUser where email='"+id+"'", SimpleUser.class).uniqueResult();

			if (usr == null) {
				session.close();
				return Util.getError("User doesn't exist", Status.NO_CONTENT);
			}

			usr.removeRole(role);

			session.beginTransaction();
			session.saveOrUpdate(usr);
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(usr.getAdminUserData()).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);

			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);

		}

	}




	//close acc
	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}/close")
	@ApiOperation(value = "Close the specific user's account",
	notes = "Returns a message if ok",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User records"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response closeAcc(@ApiParam(value = "user id", required = true) @PathParam("id") String id) {


		try {

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "UPDATE SimpleUser set isClosed = :closed WHERE uuid = :uuid";
			Query query = session.createQuery(hql);

			query.setParameter("uuid", id);
			query.setParameter("closed", true);


			query.executeUpdate();
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(new MessageData("account closed")).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}

	//reopen acc
	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}/reopen")
	@ApiOperation(value = "Reopens the specific user's account",
	notes = "Returns a message if ok",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User records"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response reopenAcc(@ApiParam(value = "user id", required = true) @PathParam("id") String id) {


		try {

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "UPDATE SimpleUser set isClosed = :closed WHERE uuid = :uuid";
			Query query = session.createQuery(hql);

			query.setParameter("uuid", id);
			query.setParameter("closed", false);


			query.executeUpdate();
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(new MessageData("account reopened")).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}


	//lock acc
	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}/lock")
	@ApiOperation(value = "Lock the specific user's account",
	notes = "Returns a message if ok",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User records"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response lockAcc(@ApiParam(value = "user id", required = true) @PathParam("id") String id) {


		try {

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "UPDATE SimpleUser set isLocked = :locked WHERE uuid = :uuid";
			Query query = session.createQuery(hql);

			query.setParameter("uuid", id);
			query.setParameter("locked", true);


			query.executeUpdate();
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity(new MessageData("account locked")).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}

	//unlock acc
	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}/unlock")
	@ApiOperation(value = "Unlock the specific user's account",
	notes = "Returns a message if ok",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User records"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response unlockAcc(@ApiParam(value = "user id", required = true) @PathParam("id") String id) {


		try {

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "UPDATE SimpleUser set isLocked = :locked WHERE uuid = :uuid";
			Query query = session.createQuery(hql);

			query.setParameter("uuid", id);
			query.setParameter("locked", false);


			query.executeUpdate();
			session.getTransaction().commit();

			session.close();

			return Response.ok().entity("account unlocked").build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}

	//del acc
	@DELETE
	@RolesAllowed(Roles.ADMIN)
	@Path("user/{id}")
	@ApiOperation(value = "Delete the specific user's account",
	notes = "Returns a message if ok",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "User records"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response deleteAcc(@ApiParam(value = "user id", required = true) @PathParam("id") String id) {

		try {

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "DELETE FROM SimpleUser "  + 
					"WHERE uuid = :uuid";
			Query query = session.createQuery(hql);
			query.setParameter("uuid", id);

			query.executeUpdate();
			session.getTransaction().commit();

			session.close();
			return Response.ok().entity("account deleted").build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}

	////////////////////////////////////////////////

	//email services

	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("triggers")
	@ApiOperation(value = "Get the available email triggers",
	notes = "Returns the email triggers",
	response = MailTriggers.class,
	responseContainer = "List"
			)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Email triggers")
	})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response getTriggers() {

		List<MailTriggers> reply = new ArrayList<MailTriggers>();

		for (MailTriggers tag: MailTriggers.values()) {

			reply.add(tag);
		}

		return Response.ok().entity(reply).build();


	}

	//get messages
	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("mail")
	@ApiOperation(value = "Get the configured email messages",
	notes = "Returns the configured messages",
	response = SimpleEmail.class,
	responseContainer = "List")
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Email messages"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response getMessages() {

		try {
			Session session=config.getSession();

			List<SimpleEmail> emails = session.createQuery("from SimpleEmail", SimpleEmail.class).list();

			session.close();

			return Response.ok().entity(emails).build();
		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}

	//get message
	@GET
	@RolesAllowed(Roles.ADMIN)
	@Path("mail/{trigger}")
	@ApiOperation(value = "Get the email message for the specified trigger",
	notes = "Returns the configured message",
	response = SimpleEmail.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Email message"),
			@ApiResponse(code = 400, message = "Invalid trigger"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response getMessage(@ApiParam(value = "email trigger", required = true) @PathParam("trigger") String trigger) {

		boolean valid=false;

		for (MailTriggers tag: MailTriggers.values()) {
			if (tag.trigger().equals(trigger)) {
				valid=true;
			}
		}

		if (!valid) {
			return Util.getError("Invalid trigger", Status.BAD_REQUEST);
		}

		try {
			Session session=config.getSession();

			SimpleEmail email = session.createQuery("from SimpleEmail where triggerTag='"+trigger+"'", SimpleEmail.class).uniqueResult();

			session.close();


			return Response.ok().entity(email).build();
		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}

	@DELETE
	@RolesAllowed(Roles.ADMIN)
	@Path("mail/{trigger}")
	@ApiOperation(value = "Delete the email message for the specified trigger",
	notes = "Returns a confirmation message",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Confirmation message"),
			@ApiResponse(code = 400, message = "Invalid trigger"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	public Response deleteMail(@ApiParam(value = "email trigger", required = true) @PathParam("trigger") String trigger) {

		try {

			boolean valid=false;

			for (MailTriggers tag: MailTriggers.values()) {
				if (tag.trigger().equals(trigger)) {
					valid=true;
				}
			}

			if (!valid) {
				return Util.getError("Invalid trigger", Status.BAD_REQUEST);
			}

			Session session = config.getSession();
			session.beginTransaction();

			String hql = "DELETE FROM SimpleEmail "  + 
					"WHERE triggerTag = :tag";
			Query query = session.createQuery(hql);
			query.setParameter("tag", trigger);

			query.executeUpdate();
			session.getTransaction().commit();

			session.close();
			return Response.ok().entity(new MessageData(trigger+" deleted")).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}

	}


	@POST
	@RolesAllowed(Roles.ADMIN)
	@Path("mail")
	@ApiOperation(value = "Create or update the email message for the specified trigger",
	notes = "Returns a confirmation message",
	response = MessageData.class)
	@ApiResponses(value = { 
			@ApiResponse(code = 200, message = "Confirmation message"),
			@ApiResponse(code = 400, message = "Invalid trigger"),
			@ApiResponse(code = 500, message = "Error querying database")})
	@Produces(MediaType.APPLICATION_JSON) 
	@Consumes(MediaType.APPLICATION_JSON) 
	public Response updateMail(SimpleEmail email) {

		boolean valid=false;

		for (MailTriggers tag: MailTriggers.values()) {
			if (tag.trigger().equals(email.getTriggerTag())) {
				valid=true;
			}
		}

		if (!valid) {
			return Util.getError("Invalid trigger", Status.BAD_REQUEST);
		}


		try {
			Session session = config.getSession();
			session.beginTransaction();
			session.saveOrUpdate(email);
			session.getTransaction().commit();

			session.close();
			return Response.ok().entity(new MessageData("message created")).build();

		} catch (Exception e) {
			LOG.error("Error querying database", e);
			return Util.getError("Error querying database", Status.INTERNAL_SERVER_ERROR);
		}
	}

}
