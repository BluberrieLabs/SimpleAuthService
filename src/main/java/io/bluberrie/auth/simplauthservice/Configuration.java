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

import java.io.File;
import java.io.FileReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Security;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.ServletContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.internal.SessionFactoryImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.mail.MailSender;


public class Configuration implements Map {

	private SessionFactory sessionFactory;
	private final StandardServiceRegistry registry;

	private Key privateKey;
	private Key publicKey;

	private MailSender mailer;

	private static final Logger LOG = LoggerFactory
			.getLogger(Configuration.class);

	private static final HashMap<String, Configuration> instances = new HashMap<>();
	private static final ScriptEngine groovy = new ScriptEngineManager().getEngineByName("groovy");

	//default locations for the configuration file
	public static File[] locations = {
			new File("/etc/sas/sas.properties"),
			new File(new File(System.getProperty("user.home")), ".sas/sas.properties")
	};



	public static synchronized Configuration getInstance(String context) {
		if (!instances.containsKey(context)) {
			instances.put(context, new Configuration(context));
		}
		return instances.get(context);
	}

	public static synchronized Configuration forContext(ServletContext ctx) {
		String ctxpath=ctx.getContextPath();

		if (ctxpath.length() > 1) {
			return getInstance(ctxpath.substring(1));
		} else {
			return getInstance();
		}
	}

	public static synchronized Configuration getInstance() {
		return Configuration.getInstance("default");
	}

	private final Properties props;
	private final String context;

	public Configuration(String context) {

		this.props=new Properties();

		//default properties
		props.setProperty("redirecturl", "https://www.google.com");
		props.setProperty("sas-user", "admin@foo.com");
		props.setProperty("sas-passwd", "changeme");
		props.setProperty("apikey", "1234567");
		props.setProperty("jwt-audience", "blahblah");
		props.setProperty("jwt-lifetime", "86400000");
		props.setProperty("jwt-web-lifetime", "43200000");
		props.setProperty("pwd-reset-lifetime", "3600000");
		props.setProperty("jwt-refresh-lifetime", "31536000000");
		props.setProperty("jwt-refresh-audience", "sas-renewer");
		props.setProperty("jwt-issuer", "foo.bar.com");
		props.setProperty("facebook-id", "");
		props.setProperty("facebook-secret", "");
		props.setProperty("publickey", "");
		props.setProperty("privatekey", "");

		this.context=context;

		for (File location : locations) {
			if (!location.exists()) {
				continue;
			}
			LOG.info("Reading configuration from " + location);
			try {
				props.load(new FileReader(location));

				LOG.debug(this.toString());
			} catch (Exception ex) {
				LOG.error("Failed to load configuration from " + location, null, ex);
			}
		}
		//open connection      

		//load config defaults. These can be overridden in the sas.properties file
		org.hibernate.cfg.Configuration config = new org.hibernate.cfg.Configuration();
		config.configure("/hibernate.cfg.xml");

		config.addAnnotatedClass(io.bluberrie.auth.simplauthservice.persist.SimpleUser.class);
		config.addAnnotatedClass(io.bluberrie.auth.simplauthservice.persist.SimpleEmail.class);
		config.addAnnotatedClass(io.bluberrie.auth.simplauthservice.persist.SimpleRefreshToken.class);

		//LOG.info("Hibernate config 1: "+config.toString());

		LOG.debug("Hibernate config 2: "+config.getProperties().toString());

		for (String hkey: (Set<String>) this.keySet()) {
			if (hkey.startsWith("hibernate.")) {
				try {
					LOG.info("Adding hibernate key "+hkey + ", value: "+(String)this.get(hkey));
					config.getProperties().remove(hkey);

					config.setProperty(hkey, (String)this.get(hkey));

				} catch (Exception ex) {
					LOG.error("Exception", ex);
				}
			}

		}

		LOG.debug("Hibernate config 3: "+config.getProperties().toString());


		registry = new StandardServiceRegistryBuilder().applySettings(config.getProperties()).build();

		try {
			sessionFactory = config.buildSessionFactory(registry);

			LOG.info("Created hibernate session factory");
		} catch (Exception e) {

			LOG.error("Can't create session factory", e);

			StandardServiceRegistryBuilder.destroy(registry);
		}

		Security.addProvider(new BouncyCastleProvider());
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

			publicKey = Util.loadPublicKey(factory, (String) this.get("publickey"));
			privateKey = Util.loadPrivateKey(factory, (String) this.get("privatekey"));

			//pass properties to the emailer
			Properties mailProps = new Properties();
			for (String hkey: (Set<String>) this.keySet()) {
				if (hkey.startsWith("mail.")) {
					mailProps.setProperty(hkey, (String)this.get(hkey));
				}
			}

			this.mailer = new MailSender(mailProps, this);


		} catch (Exception e) {
			LOG.error("Error loading keys", e);
		}


	}



	public void closeConnection() {
		SessionFactoryImpl sessionFactoryImpl = (SessionFactoryImpl) sessionFactory;
		String url = props.get("hibernate.connection.url").toString();

		LOG.info("CLOSING CONNECTIONS");
		if ( sessionFactory != null ) {
			sessionFactory.close();
		}
		StandardServiceRegistryBuilder.destroy(registry);

		LOG.info("trying to unload driver for "+url);

		Driver driver;
		try {
			driver = DriverManager.getDriver(url);
			DriverManager.deregisterDriver(driver);

		} catch (SQLException e) {
			LOG.error("Couldn't unload driver");
		}


	}


	@Override
	public void finalize() {
		this.closeConnection();
	}

	public Session getSession() {
		return sessionFactory.openSession();
	}

	public MailSender getMailSender() {
		return mailer;
	}

	public Key getJWTPrivateKey() {
		return privateKey;
	}

	public Key getJWTPublicKey() {
		return publicKey;
	}

	public String getPublicKeyFile() {
		return (String) this.get("publickey");
	}

	public String getServerURL() {
		return (String) this.get("serverurl");
	}

	public String getResetURL() {
		return (String) this.get("reseturl");
	}

	public String getDefaultUser() {
		return (String) this.get("sas-user");
	}

	public String getTokenIssuer() {
		return (String) this.get("jwt-issuer");
	}

	public String getConfirmRedirect() {
		return (String) this.get("redirecturl");
	}

	public long getTokenLife() {
		return Long.parseLong((String)this.get("jwt-lifetime"));
	}

	public long getWebTokenLife() {
		return Long.parseLong((String)this.get("jwt-web-lifetime"));
	}

	public long getRefreshTokenLife() {
		return Long.parseLong((String)this.get("jwt-refresh-lifetime"));
	}

	public long getResetTokenLife() {
		return Long.parseLong((String)this.get("pwd-reset-lifetime"));
	}

	public String getFBAppID() {
		return (String) this.get("facebook-id");
	}

	public String getFBAppSecret() {
		return (String) this.get("facebook-secret");
	}

	public String getAPIKey() {
		return (String) this.get("apikey");
	}

	public String getJWTAudience() {
		return (String) this.get("jwt-audience");
	}

	public String getRefreshAudience() {
		return (String) this.get("jwt-refresh-audience");
	}

	public String getDefaultPassword() {
		return (String) this.get("sas-passwd");
	}


	///map stuff
	@Override
	public int size() {
		return props.size();
	}

	@Override
	public boolean isEmpty() {
		return props.isEmpty();
	}

	@Override
	public boolean containsKey(Object key) {
		String k = (String) key;
		String ctxKey = context + "." + k;
		return props.containsKey(ctxKey) || props.containsKey(k);
	}

	@Override
	public boolean containsValue(Object value) {
		return props.containsValue(value);
	}

	@Override
	public Object get(Object key) {
		String k = (String) key;
		String ctxKey = context + "." + k;
		String result;

		if (props.containsKey(ctxKey)) {
			result = (String) props.get(ctxKey);
		} else {

			result = (String) props.get(key);
		}
		try {
			return groovy.eval(result);
		} catch (Exception ex) {
			return result;
		}
	}

	public boolean getBool(String key) {
		String v = ((String) this.get(key)).toLowerCase();
		if (v == "true" || v == "1" || v == "on") {
			return true;
		} else {
			return false;
		}
	}

	@Override
	public Object put(Object key, Object value) {
		throw new UnsupportedOperationException("Configuration objects are read-only.");
	}

	@Override
	public Object remove(Object key) {
		throw new UnsupportedOperationException("Configuration objects are read-only.");
	}

	@Override
	public void putAll(Map m) {
		throw new UnsupportedOperationException("Configuration objects are read-only.");
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException("Configuration objects are read-only.");
	}

	@Override
	public Set<?> keySet() {
		return props.keySet();
	}

	@Override
	public Collection<?> values() {
		return props.values();
	}

	@Override
	public Set<?> entrySet() {
		return props.entrySet();
	}

	@Override
	public String toString() {
		StringBuilder result = new StringBuilder();
		result.append("Configuration:\n");
		for (String key : (Set<String>) this.keySet()) {
			Object value = this.get(key);
			result.append("  ");
			result.append(key);
			result.append(" = (");
			result.append(value.getClass().getName());
			result.append(") ");
			result.append(value.toString());
			result.append("\n");
		}
		return result.toString();
	}
}

