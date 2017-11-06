package io.bluberrie.auth.simplauthservice.blobs;

import java.util.Date;

public class UserData {

	private Date created;
	private Date last;
	private String userid;
	private String fullname;	
	private String role;	
	private String email;	
	private boolean locked;	
	private boolean closed;	
	private boolean confirmed;	
	private boolean facebook;
	
	public UserData(Date created, Date last, String userid, String fullname, String role, String email,
			boolean locked, boolean closed, boolean confirmed, boolean facebook) {
		super();
		this.created = created;
		this.last = last;
		this.userid = userid;
		this.fullname = fullname;
		this.role = role;
		this.email = email;
		this.locked = locked;
		this.closed = closed;
		this.confirmed = confirmed;
		this.facebook = facebook;
	}

	public UserData(Date created, Date last, String userid, String fullname, String role, String email) {
		super();
		this.created = created;
		this.last = last;
		this.userid = userid;
		this.fullname = fullname;
		this.role = role;
		this.email = email;
	}

	public Date getCreated() {
		return created;
	}

	public void setCreated(Date created) {
		this.created = created;
	}

	public Date getLast() {
		return last;
	}

	public void setLast(Date last) {
		this.last = last;
	}

	public String getUserid() {
		return userid;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

	public String getFullname() {
		return fullname;
	}

	public void setFullname(String fullname) {
		this.fullname = fullname;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public boolean isLocked() {
		return locked;
	}

	public void setLocked(boolean locked) {
		this.locked = locked;
	}

	public boolean isClosed() {
		return closed;
	}

	public void setClosed(boolean closed) {
		this.closed = closed;
	}

	public boolean isConfirmed() {
		return confirmed;
	}

	public void setConfirmed(boolean confirmed) {
		this.confirmed = confirmed;
	}

	public boolean isFacebook() {
		return facebook;
	}

	public void setFacebook(boolean facebook) {
		this.facebook = facebook;
	}
	
	
	
	
}
