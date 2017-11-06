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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.json.JSONObject;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.Util;
import io.bluberrie.auth.simplauthservice.blobs.UserData;
import io.bluberrie.auth.simplauthservice.security.Roles;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
@Entity
@Table( name = "SASUSERS" )

public class SimpleUser {

	@Id
	@Column(name="USERID")
	private String uuid;		
	private Date creation_date;
	private String fullname;
	private String password;
	private Date last_login; 
	private String facebookid; 
	private String roles;

	private String resetToken=null;
	private Date resetTokenExpires=null;

	@Column(name = "EMAIL", unique=true)
	private String email;

	private boolean isLocked;
	private boolean emailConfirmed;
	private boolean isClosed;
	private String resetKey=null;

	@OneToMany(
			mappedBy = "user", 
			cascade = CascadeType.ALL, 
			orphanRemoval = true
			)
	private List<SimpleRefreshToken> refreshTokens=new ArrayList<SimpleRefreshToken>();


	public SimpleUser() {
		super();
		this.uuid = "";
		this.creation_date = new Date();
		this.fullname = "";
		this.password = null;
		this.roles = Roles.USER;
		this.last_login = creation_date;
		this.email = "";
		this.facebookid="";
		this.isLocked=false;
		this.isClosed=false;
		this.emailConfirmed=false;
	}

	public SimpleUser(String name, String passwd, String email) {
		super();
		this.uuid = UUID.randomUUID().toString();
		this.creation_date = new Date();
		this.fullname = name;
		this.password = new String(Util.hashPassword(passwd.toCharArray(), uuid.getBytes(), 3, 256));
		this.roles = Roles.USER;
		this.last_login = creation_date;
		this.email = email;
		this.isLocked=false;
		this.isClosed=false;
		this.facebookid="";
		this.emailConfirmed=false;

	}




	public String getResetToken() {
		return resetToken;
	}

	public void setResetToken(String resetToken) {
		this.resetToken = resetToken;
	}

	public Date getResetTokenExpires() {
		return resetTokenExpires;
	}

	public void setResetTokenExpires(Date resetTokenExpires) {
		this.resetTokenExpires = resetTokenExpires;
	}

	public List<SimpleRefreshToken> getRefreshTokens() {
		return refreshTokens;
	}

	public void addRefreshToken(SimpleRefreshToken token) {
		refreshTokens.add(token);
		token.setUser(this);
	}

	public void removeRefreshToken(SimpleRefreshToken token) {
		refreshTokens.remove(token);
		token.setUser(null);
	}

	public boolean isEmailConfirmed() {
		return emailConfirmed;
	}

	public void setEmailConfirmed(boolean emailConfirmed) {
		this.emailConfirmed = emailConfirmed;
	}

	public String getFacebookid() {
		return facebookid;
	}

	public void setFacebookid(String facebookid) {
		this.facebookid = facebookid;
	}

	public Date getLast_login() {
		return last_login;
	}

	public void setLast_login(Date last_login) {
		this.last_login = last_login;
	}

	public boolean isLocked() {
		return isLocked;
	}

	public void setLocked(boolean locked) {
		this.isLocked = locked;
	}

	public boolean isClosed() {
		return isClosed;
	}

	public void setClosed(boolean closed) {
		this.isClosed = closed;
	}

	public String getResetKey() {
		return resetKey;
	}

	public void setResetKey(String resetKey) {
		this.resetKey = resetKey;
	}

	public String getUuid() {
		return uuid;
	}
	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public Date getCreation_date() {
		return creation_date;
	}
	public void setCreation_date(Date creation_date) {
		this.creation_date = creation_date;
	}
	public String getFullname() {
		return fullname;
	}
	public void setFullname(String fullname) {
		this.fullname = fullname;
	}

	public void setPassword(String passwd) {
		this.password = new String(Util.hashPassword(passwd.toCharArray(), uuid.getBytes(), 3, 256));
	}
	public String getRoles() {
		return roles;
	}

	public boolean hasRole(String role) {
		return roles.contains(role);
	}

	public void addRole(String role) {

		List<String> roleslist=new ArrayList<String>(Arrays.asList(roles.split(":")));


		System.out.println("ROLES: "+roles);

		System.out.println("LISTSIZE: "+roleslist.size());

		roleslist.add(role);

		StringBuilder sb = new StringBuilder();
		int i = 1;
		for (String r: roleslist) {
			sb.append(r);

			if (i++ != roleslist.size()) {
				sb.append(":");
			}
		}

		roles=sb.toString();

	}

	public void removeRole(String role) {
		List<String> roleslist=new ArrayList<String>(Arrays.asList(roles.split(":")));

		roleslist.remove(role);

		StringBuilder sb = new StringBuilder();
		int i = 1;
		for (String r: roleslist) {
			sb.append(r);

			if (i++ != roleslist.size()) {
				sb.append(":");
			}
		}

		roles=sb.toString();		}


	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}

	public UserData getUserData() {
		UserData userData = new UserData(creation_date, last_login, uuid, fullname, getRoles(), email);
		
		return userData;
	}

	public UserData getAdminUserData() {
		
		
		boolean facebook = false;
		
		if (facebookid != null && !facebookid.isEmpty()) {
			facebook = true;
		}
		
		UserData userData = new UserData(creation_date, last_login, uuid, fullname, getRoles(), email, isLocked, isClosed, emailConfirmed, facebook);
		
		return userData;
	}

	public boolean validatePassword (String passwd) {

		String hashpwd = new String(Util.hashPassword(passwd.toCharArray(), uuid.getBytes(), 3, 256));

		System.out.println("PASSWD: "+new String(hashpwd));

		return password.equals(hashpwd);

	}

	public String getJWT(Configuration config) {
		return getJWT(config, config.getTokenLife());
	}


	public String getJWT(Configuration config, long lifetime) {

		String compactJws = Jwts.builder()
				.setSubject(uuid)
				.setHeaderParam("typ", "jwt")
				.claim("name", fullname)
				.claim("scopes", Arrays.asList(roles.split(":")))
				.setExpiration(new Date(System.currentTimeMillis()+lifetime))
				.setIssuer(config.getTokenIssuer())
				.setAudience(config.getJWTAudience())
				.signWith(SignatureAlgorithm.RS512, config.getJWTPrivateKey())
				.compact();

		return compactJws;

	}

	public String getRefreshJWT(Configuration config) {


		SimpleRefreshToken jti = new SimpleRefreshToken(this);

		addRefreshToken(jti);

		String compactJws = Jwts.builder()
				.setSubject(uuid)
				.setHeaderParam("typ", "jwt")
				.claim("jti", jti.getTokenid())
				.setExpiration(new Date(System.currentTimeMillis()+config.getRefreshTokenLife()))
				.setIssuer(config.getTokenIssuer())
				.setAudience(config.getRefreshAudience())
				.signWith(SignatureAlgorithm.RS512, config.getJWTPrivateKey())
				.compact();

		return compactJws;

	}


}
