package io.bluberrie.auth.simplauthservice.blobs;

public class ErrorData {

	private String error="";

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public ErrorData(String error) {
		super();
		this.error = error;
	}
	
	
	
}
