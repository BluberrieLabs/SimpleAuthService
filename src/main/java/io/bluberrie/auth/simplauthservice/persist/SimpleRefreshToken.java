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

import java.util.UUID;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table( name = "REFRESHTOKENS" )
public class SimpleRefreshToken {

	@Id
	private String tokenid;


	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "USERID")
	private SimpleUser user;


	public SimpleRefreshToken() {
		super();
	}

	public SimpleRefreshToken(SimpleUser user) {
		super();
		tokenid = UUID.randomUUID().toString();
		this.user = user;
	}

	public String getTokenid() {
		return tokenid;
	}
	public void setTokenid(String tokenid) {
		this.tokenid = tokenid;
	}
	public SimpleUser getUser() {
		return user;
	}

	public void setUser(SimpleUser user) {
		this.user=user;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof SimpleRefreshToken )) return false;
		return tokenid != null && tokenid.equals(((SimpleRefreshToken) o).tokenid);
	}
	@Override
	public int hashCode() {
		return 31;
	}


}
