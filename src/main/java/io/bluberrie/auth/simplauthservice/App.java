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

import java.io.IOException;
import java.net.URI;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;

import org.glassfish.grizzly.http.server.HttpServer;

/**
 * @author Bluberrie Labs
 */
public class App {

	private static final URI BASE_URI = URI.create("http://localhost:8080/base/");

	public static final String ROOT_PATH = "resource-path";

	public static void main(String[] args) {
		try {
			System.out.println("SimpleAuthService");

			final HttpServer server = GrizzlyHttpServerFactory.createHttpServer(BASE_URI, new SimpleAuth(), false);
			Runtime.getRuntime().addShutdownHook(new Thread(server::shutdownNow));
			server.start();

			System.out.println(String.format(
					"Application started.\n"
							+ "Try out %s%s\n"
							+ "Stop the application using CTRL+C",
							BASE_URI, ROOT_PATH));

			Thread.currentThread().join();
		} catch (IOException | InterruptedException ex) {
			Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
		}
	}
}
