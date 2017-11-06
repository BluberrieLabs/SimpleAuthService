package io.bluberrie.auth.simplauthservice.blobs;

public class TokenData {

	private String token;
	private String refreshToken;
	public TokenData(String token, String refreshToken) {
		super();
		this.token = token;
		this.refreshToken = refreshToken;
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
	
}
