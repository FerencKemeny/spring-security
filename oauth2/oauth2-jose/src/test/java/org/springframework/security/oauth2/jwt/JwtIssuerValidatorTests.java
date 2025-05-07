/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.jwt;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtIssuerValidatorTests {

	private static final String ISSUER = "https://issuer";

	private final JwtIssuerValidator validator = new JwtIssuerValidator(ISSUER);

	@Test
	public void validateWhenAllowEmptyDefaultAndIssuerMatchesThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim("iss", ISSUER).build();
		// @formatter:off
		assertThat(this.validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	@Test
	public void validateWhenAllowEmptyFalseAndIssuerMatchesThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim("iss", ISSUER).build();
		// @formatter:off
		this.validator.setAllowEmpty(false);
		assertThat(this.validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	@Test
	public void validateWhenAllowEmptyDefaultAndIssuerUrlMatchesThenReturnsSuccess() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim("iss", new URL(ISSUER)).build();

		assertThat(this.validator.validate(jwt)).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenAllowEmptyFalseAndIssuerUrlMatchesThenReturnsSuccess() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim("iss", new URL(ISSUER)).build();

		this.validator.setAllowEmpty(false);
		assertThat(this.validator.validate(jwt)).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenAllowEmptyDefaultAndIssuerMismatchesThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "https://other").build();
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenAllowEmptyFalseAndIssuerMismatchesThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "https://other").build();
		this.validator.setAllowEmpty(false);
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenAllowEmptyDefaultAndIssuerUrlMismatchesThenReturnsError() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, new URL("https://other")).build();

		OAuth2TokenValidatorResult result = this.validator.validate(jwt);

		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenAllowEmptyFalseAndIssuerUrlMismatchesThenReturnsError() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, new URL("https://other")).build();

		this.validator.setAllowEmpty(false);
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);

		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenAllowEmptyDefaultAndJwtHasNoIssuerThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUD, "https://aud").build();
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenAllowEmptyFalseAndJwtHasNoIssuerThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUD, "https://aud").build();
		this.validator.setAllowEmpty(false);
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	// gh-6073
	@Test
	public void validateWhenAllowEmptyDefaultAndIssuerMatchesAndIsNotAUriThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "issuer").build();
		JwtIssuerValidator validator = new JwtIssuerValidator("issuer");
		// @formatter:off
		assertThat(validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	// gh-6073
	@Test
	public void validateWhenAllowEmptyFalseAndIssuerMatchesAndIsNotAUriThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "issuer").build();
		JwtIssuerValidator validator = new JwtIssuerValidator("issuer");
		validator.setAllowEmpty(false);
		// @formatter:off
		assertThat(validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	@Test
	public void validateWhenAllowEmptyDefaultAndJwtIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.validator.validate(null));
		// @formatter:on
	}

	@Test
	public void validateWhenAllowEmptyFalseAndJwtIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		this.validator.setAllowEmpty(false);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.validator.validate(null));
		// @formatter:on
	}

	@Test
	public void constructorWhenRequiredDefaultAndNullIssuerIsGivenThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerValidator(null));
		// @formatter:on
	}

}
