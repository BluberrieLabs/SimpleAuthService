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
package io.bluberrie.auth.simplauthservice.security;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;

import org.hibernate.Session;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bluberrie.auth.simplauthservice.Configuration;
import io.bluberrie.auth.simplauthservice.DispatchException;
import io.bluberrie.auth.simplauthservice.persist.SimpleUser;

public class FacebookAuth {

	private static final Logger LOG = LoggerFactory.getLogger(FacebookAuth.class);


	private String appToken;
	private static String GRAPHENDPOINT = "https://graph.facebook.com";
	private static String GRAPHVERSION = "v2.9";

	private Configuration config;

	public FacebookAuth(Configuration config) {

		this.config=config;
		getAppToken();
	}


	public SimpleUser authWithFacebook(String fbToken) throws DispatchException {

		if (appToken == null) {
			throw new DispatchException("Error getting Facebook auth token");
		}

		//get FB ID and email
		String graphNode="debug_token";
		Map <String, String> params = new HashMap<String, String>();
		params.put("input_token", fbToken);
		params.put("access_token", appToken);

		String fbid, name, email;

		try {
			String response = fbHttpClient(graphNode, null, params);

			JSONObject object = new JSONObject(response);

			fbid=object.getJSONObject("data").getString("user_id");

			if (fbid==null || fbid.isEmpty()) {
				throw new DispatchException("Error getting Facebook id");
			}

			params.clear();
			params.put("access_token", appToken);
			params.put("fields", "name,email");
			graphNode="/"+GRAPHVERSION+"/"+fbid;

			response = fbHttpClient(graphNode, null, params);

			JSONObject profile = new JSONObject(response);

			name=profile.getString("name");
			email=profile.getString("email");

			if (name==null || name.isEmpty()) {
				throw new DispatchException("Error getting Facebook name");
			}

			if (email==null || email.isEmpty()) {
				throw new DispatchException("Error getting Facebook email");
			}

		} catch (DispatchException e) {
			throw new DispatchException("Error connecting to Facebook");

		}


		//check for existing user

		Session session = config.getSession();

		SimpleUser usr = (SimpleUser)session.createQuery("from SimpleUser where email='"+email+"'").uniqueResult();

		if (usr==null) {
			usr = new SimpleUser(name, UUID.randomUUID().toString(), email);  //create new account with random password
		}

		usr.setFacebookid(fbid);
		usr.setEmailConfirmed(true);
		usr.setLast_login(new Date());

		session.beginTransaction();
		session.saveOrUpdate(usr);
		session.getTransaction().commit();
		session.close();

		return usr;

	}

	private void getAppToken() {

		String graphNode = "oauth/access_token";
		Map <String, String> params = new HashMap<String, String>();
		params.put("client_secret", config.getFBAppSecret());
		params.put("client_id", config.getFBAppID());
		params.put("grant_type", "client_credentials");

		try {
			String response = fbHttpClient(graphNode, null, params);

			JSONObject object = new JSONObject(response);

			appToken=(String)object.get("access_token");

		} catch (DispatchException e) {
			appToken=null;
			LOG.error("Error getting app tokne: ", e);

		}



	}

	private String fbHttpClient (String apiCall, String payload, Map<String, String> params) throws DispatchException {
		try {

			String endpoint = GRAPHENDPOINT+"/"+apiCall;

			if (params != null && params.size() > 0) {

				StringBuilder result = new StringBuilder();
				boolean first = true;

				for (String pair : params.keySet())
				{
					if (first)
						first = false;
					else
						result.append("&");

					result.append(URLEncoder.encode(pair, "UTF-8"));
					result.append("=");
					result.append(URLEncoder.encode(params.get(pair), "UTF-8"));
				}

				endpoint=endpoint+"?"+result.toString();

			}

			URL obj = new URL(endpoint);
			HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

			LOG.debug("Calling endpoint: "+endpoint);

			con.setRequestMethod("GET");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("User-Agent", "curl/7.45.0");

			con.setDoOutput(true);
			if (payload != null) {
				DataOutputStream wr = new DataOutputStream(con.getOutputStream());
				wr.writeBytes(payload.toString());
				wr.flush();
				wr.close();
				LOG.debug("Sending facebook: " +payload.toString());

			}
			int responseCode = con.getResponseCode();

			LOG.debug("Facebook response Code : " + responseCode);

			BufferedReader in = new BufferedReader(
					new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();

			LOG.debug("Facebook response: "+response.toString());

			if (responseCode < 200 || responseCode > 299) {
				LOG.error("Error connecting to Facebook: "+ response.toString());
				throw new DispatchException("Error connecting to Facebook: "+ response.toString());
			}

			return response.toString();

		} catch (Exception e) {
			LOG.error("Error connecting to Facebook", e);
			throw new DispatchException("Error connecting to Facebook", e);
		}
	}

}
