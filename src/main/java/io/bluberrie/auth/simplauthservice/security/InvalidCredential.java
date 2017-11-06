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

public class InvalidCredential extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Creates a new instance of <code>InvalidCredential</code> without detail
	 * message.
	 */
	public InvalidCredential() {
	}

	/**
	 * Constructs an instance of <code>InvalidCredential</code> with the
	 * specified detail message.
	 *
	 * @param msg the detail message.
	 */
	public InvalidCredential(String msg) {
		super(msg);
	}

}

