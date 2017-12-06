package io.matthewroberts.threatlist.rest;

import org.springframework.boot.autoconfigure.web.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CustomErrorController implements ErrorController {

	private static final String PATH = "/error";
	private static final String ERROR_JSON = "{}";

	@RequestMapping(value = PATH, produces = { MediaType.APPLICATION_JSON_VALUE })
	public ResponseEntity<?> error() {
		return new ResponseEntity<String>(ERROR_JSON, HttpStatus.NOT_FOUND);
	}

	@Override
	public String getErrorPath() {
		return PATH;
	}
}
