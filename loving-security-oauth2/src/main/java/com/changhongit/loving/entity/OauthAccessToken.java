package com.changhongit.loving.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.sql.Blob;

@Entity
@Table(name = "oauth_access_token")
public class OauthAccessToken {

	@Id
	@Column(name = "token_id")
	private String tokenId;

	@Column(name = "token")
	private Blob token;

	@Column(name = "authentication_id")
	private String authlicationId;

	@Column(name = "user_name")
	private String username;

	@Column(name = "client_id")
	private String clientId;

	@Column(name = "authentication")
	private Blob authentication;

	@Column(name = "refresh_token")
	private String refreshToken;

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public String getAuthlicationId() {
		return authlicationId;
	}

	public void setAuthlicationId(String authlicationId) {
		this.authlicationId = authlicationId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public Blob getToken() {
		return token;
	}

	public void setToken(Blob token) {
		this.token = token;
	}

	public Blob getAuthentication() {
		return authentication;
	}

	public void setAuthentication(Blob authentication) {
		this.authentication = authentication;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

}
