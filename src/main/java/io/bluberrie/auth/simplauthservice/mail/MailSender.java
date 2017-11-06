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
package io.bluberrie.auth.simplauthservice.mail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.persist.SimpleEmail;

public class MailSender {

	private Transport bus;
	private static final Logger LOG = LoggerFactory.getLogger(MailSender.class);
	private Session session;
	private Configuration config;

	public MailSender(Properties prop, Configuration config) {
		this.config=config;

		session = Session.getInstance(prop);

		try {
			bus = session.getTransport("smtp");
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			LOG.error("Error creating mail transport", e);
		}

	}

	public boolean sendMessage(MailTriggers trigger, String address, String name) {
		return sendMessage(trigger, address, name, null);
	}

	public boolean sendMessage(MailTriggers trigger, String address, String name, String url) {

		//get message
		org.hibernate.Session dbsesh = config.getSession();

		SimpleEmail message = dbsesh.createQuery("from SimpleEmail where triggerTag='"+trigger.trigger()+"'", SimpleEmail.class).uniqueResult();

		if (message == null) {	
			LOG.error("Message "+trigger+" is not available");
			return false;
		}
		//replace NAME. CLICKURL
		String body = message.getBody();

		body = body.replaceFirst("NAME", name);

		if (url != null) {
			body =body.replaceFirst("CLICKURL", url);
		}

		//Send message
		try {
			bus.connect();

			// Instantiate a message
			Message msg = new MimeMessage(session);

			// Set message attributes
			msg.setFrom(new InternetAddress(message.getSender(), message.getPersonal()));

			InternetAddress[] addresses = {new InternetAddress(address)};


			msg.setRecipients(Message.RecipientType.TO, addresses);

			msg.setSubject(message.getSubject());
			msg.setSentDate(new Date());

			if (body.contains("<html")) {
				msg.setDataHandler(new DataHandler(new HTMLDataSource(body)));
			} else {
				msg.setText(body);
			}

			msg.saveChanges();
			bus.sendMessage(msg, addresses);

			bus.close();

			return true;

		} catch (MessagingException | UnsupportedEncodingException e) {
			LOG.error("Error sending message");
			LOG.debug("Exception", e);
			return false;
		}


	}

	@Override
	public void finalize () {
		try {
			bus.close();
		} catch (MessagingException e) {

		}
	}

	static class HTMLDataSource implements DataSource {
		private String html;

		public HTMLDataSource(String htmlString) {
			html = htmlString;
		}

		// Return html string in an InputStream.
		// A new stream must be returned each time.
		@Override
		public InputStream getInputStream() throws IOException {
			if (html == null) throw new IOException("Null HTML");
			return new ByteArrayInputStream(html.getBytes());
		}

		@Override
		public OutputStream getOutputStream() throws IOException {
			throw new IOException("This DataHandler cannot write HTML");
		}

		@Override
		public String getContentType() {
			return "text/html";
		}

		@Override
		public String getName() {
			return "HTML email sender";
		}
	}

}
