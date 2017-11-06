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
package io.bluberrie.auth.simplauthservice.persist;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;


@Entity
@Table( name = "SASEMAIL" )
public class SimpleEmail {

	@Id
	//@Column(name = "TRIGGER", unique=true)
	private String triggerTag;
	private String sender;
	private String subject;
	private String personal;


	@Column(name = "body", columnDefinition="TEXT")
	private String body;

	public SimpleEmail() {
		super();
	}

	public SimpleEmail(String sender, String subject, String body, String triggerTag, String personal) {
		super();
		this.sender = sender;
		this.subject = subject;
		this.body = body;
		this.triggerTag = triggerTag;
		this.personal = personal;
	}



	public String getPersonal() {
		return personal;
	}

	public void setPersonal(String personal) {
		this.personal = personal;
	}

	public String getSender() {
		return sender;
	}
	public void setSender(String sender) {
		this.sender = sender;
	}
	public String getSubject() {
		return subject;
	}
	public void setSubject(String subject) {
		this.subject = subject;
	}
	public String getBody() {
		return body;
	}
	public void setBody(String body) {
		this.body = body;
	}

	public String getTriggerTag() {
		return triggerTag;
	}

	public void setTriggerTag(String triggerTag) {
		this.triggerTag = triggerTag;
	}





}
