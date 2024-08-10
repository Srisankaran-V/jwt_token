package com.security.drugInventory.unittest;


import com.security.drugInventory.auth.AuthenticationRequest;
import com.security.drugInventory.auth.AuthenticationResponse;
import com.security.drugInventory.auth.AuthenticationService;
import com.security.drugInventory.auth.RegisterRequest;
import com.security.drugInventory.config.JWTService;
import com.security.drugInventory.user.Role;
import com.security.drugInventory.user.User;
import com.security.drugInventory.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JWTService jwtService;

    @InjectMocks
    private AuthenticationService authenticationService;
    @Mock(lenient = true)
    private AuthenticationManager authenticationManager;

    @Test
    void testRegister_Success() {
        // Arrange
        RegisterRequest request = RegisterRequest.builder()
                .email("user@example.com")
                .password("password")
                .firstname("John")
                .lastname("Doe")
                .role("USER")
                .build();

        // Mock user repository to return an empty Optional (user does not exist)
        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());

        // Mock password encoder to return encoded password
        when(passwordEncoder.encode(request.getPassword())).thenReturn("encodedPassword");

        // Create a user object and mock user repository save method
        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password("encodedPassword")
                .role(Role.USER)
                .build();
        when(userRepository.save(any(User.class))).thenReturn(user);

        // Mock JWT service to return a mock token
        when(jwtService.generateToken(user)).thenReturn("mockToken");

        // Act
        AuthenticationResponse response = authenticationService.register(request);

        // Assert
        assertNotNull(response);
        assertEquals("mockToken", response.getToken());
    }
    @Test
    void testRegister_UserAlreadyExists() {
        // Arrange
        RegisterRequest request = RegisterRequest.builder()
                .email("user@example.com")
                .password("password")
                .firstname("John")
                .lastname("Doe")
                .role("USER")
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(new User()));

        // Act & Assert
        Exception exception = assertThrows(RuntimeException.class, () -> {
            authenticationService.register(request);
        });
        assertEquals("User already exists with email: " + request.getEmail(), exception.getMessage());
    }
    @Test
    void testAuthenticate_Success() {
        // Arrange
        AuthenticationRequest request = AuthenticationRequest.builder()
                .email("user@example.com")
                .password("password")
                .build();

        User user = User.builder()
                .email(request.getEmail())
                .password("encodedPassword")
                .role(Role.USER)
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(jwtService.generateToken(user)).thenReturn("mockToken");

        // Act
        AuthenticationResponse response = authenticationService.authenticate(request);

        // Assert
        assertNotNull(response);
        assertEquals("mockToken", response.getToken());
    }

    @Test
    void testAuthenticate_FailureIncorrectPassword() {
        // Arrange
        AuthenticationRequest request = AuthenticationRequest.builder()
                .email("user@example.com")
                .password("wrongPassword")
                .build();

        User user = User.builder()
                .email(request.getEmail())
                .password("encodedPassword") // This should be the encoded password
                .role(Role.USER)
                .build();

        //when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new AuthenticationException("Invalid credentials") {});

        // Act & Assert
        RuntimeException thrown = assertThrows(RuntimeException.class, () -> {
            authenticationService.authenticate(request);
        });

        assertEquals("Invalid credentials", thrown.getMessage());
    }




    @Test
    void testGenerateToken() {
        // Arrange
        User user = User.builder()
                .email("user@example.com")
                .role(Role.USER)
                .build();

        // Mock JWT service to return a mock token
        when(jwtService.generateToken(user)).thenReturn("mockToken");

        // Act
        String token = jwtService.generateToken(user);

        // Assert
        assertNotNull(token); // Check if token is not null
        assertEquals("mockToken", token); // Optionally, check if the token matches the expected value
    }

    @Test
    void testRegister_SuccessWithDifferentRoles() {
        // Arrange for USER role
        RegisterRequest userRequest = RegisterRequest.builder()
                .email("user@example.com")
                .password("password")
                .firstname("John")
                .lastname("Doe")
                .role("USER")
                .build();

        // Mock the user repository behavior
        when(userRepository.findByEmail(userRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(userRequest.getPassword())).thenReturn("encodedPassword");

        User user = User.builder()
                .firstname(userRequest.getFirstname())
                .lastname(userRequest.getLastname())
                .email(userRequest.getEmail())
                .password("encodedPassword")
                .role(Role.USER)
                .build();
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(jwtService.generateToken(user)).thenReturn("mockToken");

        // Act
        AuthenticationResponse response = authenticationService.register(userRequest);

        // Assert
        assertNotNull(response);
        assertEquals("mockToken", response.getToken());

        // Repeat similar steps for DOCTOR and ADMIN roles
        RegisterRequest doctorRequest = RegisterRequest.builder()
                .email("doctor@example.com")
                .password("password")
                .firstname("Jane")
                .lastname("Doe")
                .role("DOCTOR")
                .build();

        when(userRepository.findByEmail(doctorRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(doctorRequest.getPassword())).thenReturn("encodedPassword");
        User doctor = User.builder()
                .firstname(doctorRequest.getFirstname())
                .lastname(doctorRequest.getLastname())
                .email(doctorRequest.getEmail())
                .password("encodedPassword")
                .role(Role.DOCTOR)
                .build();
        when(userRepository.save(any(User.class))).thenReturn(doctor);
        when(jwtService.generateToken(doctor)).thenReturn("mockToken");

        // Act
        AuthenticationResponse doctorResponse = authenticationService.register(doctorRequest);

        // Assert
        assertNotNull(doctorResponse);
        assertEquals("mockToken", doctorResponse.getToken());

        // Similarly, add for ADMIN role if needed
        User admin = User.builder()
                .email("admin@example.com")
                .password("encodedPassword")
                .role(Role.ADMIN)
                .build();

        when(userRepository.findByEmail(admin.getEmail())).thenReturn(Optional.of(admin));
        when(jwtService.generateToken(admin)).thenReturn("mockToken");

        AuthenticationRequest request = AuthenticationRequest.builder()
                .email(admin.getEmail())
                .password("password")
                .build();

        // Act
        AuthenticationResponse res = authenticationService.authenticate(request);

        // Assert
        assertNotNull(response);
        assertEquals("mockToken", res.getToken());
    }
}
