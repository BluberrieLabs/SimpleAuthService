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

import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.hibernate.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.persist.SimpleUser;
import io.bluberrie.auth.simplauthservice.security.Roles;


public class Resources implements ServletContextListener {
	public static String CONFIGURATION = "configuration";

	public Resources () {
		// TODO Auto-generated constructor stub
	}

	private static final Logger LOG = LoggerFactory.getLogger(Resources.class);

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		ServletContext ctx = sce.getServletContext();
		Configuration config = (Configuration)ctx.getAttribute(CONFIGURATION);
		config.closeConnection();		
	}

	@Override
	public void contextInitialized(ServletContextEvent sce) {
		ServletContext ctx = sce.getServletContext();

		Configuration config = Configuration.forContext(ctx);
		ctx.setAttribute(CONFIGURATION, config);		

		init(config);

	}

	public static Configuration getConfiguration(ServletContext ctx) {
		return (Configuration) ctx.getAttribute(CONFIGURATION);
	}


	public void init(Configuration config) {
		//TODO: Init DB if empty with default admin password
		LOG.info("Initialising context");

		try {

			Session session = config.getSession();

			List result = session.createQuery("from SimpleUser").list();

			if (result.isEmpty()) {
				LOG.info("DB empty. Creating admin user");

				String usr=config.getDefaultUser();
				String passwd=config.getDefaultPassword();

				SimpleUser admin = new SimpleUser("Admin", passwd, usr);
				admin.addRole(Roles.ADMIN);

				session.beginTransaction();
				session.save(admin);
				session.getTransaction().commit();

			} else {
				LOG.info("Users exists - not initialising DB");
			}
			session.close();

		} catch (Exception e) {
			LOG.error("Error initilising data ", e);
		}
	}
}

