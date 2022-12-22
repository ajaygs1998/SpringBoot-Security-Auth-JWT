package com.cybage.globaExceptions;



import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import org.springframework.http.HttpStatus;

@ControllerAdvice
public class GlobalExceptions extends ResponseEntityExceptionHandler {

	@ExceptionHandler(RecordNotFoundException.class)
	public ResponseEntity<String> handleExceptions(RecordNotFoundException exception) {

		return new ResponseEntity<String>(exception.getMessage(), HttpStatus.NOT_FOUND);

	}

}
