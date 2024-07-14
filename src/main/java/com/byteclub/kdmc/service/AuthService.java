package com.byteclub.kdmc.service;

import com.byteclub.kdmc.dto.LoginDTO;
import com.byteclub.kdmc.dto.SignUpDTO;
import com.byteclub.kdmc.dto.StudentResponseDTO;
import com.byteclub.kdmc.exception.InvalidCredentials;
import com.byteclub.kdmc.exception.InvalidUserSessionException;
import com.byteclub.kdmc.exception.ResourceNotFoundException;
import com.byteclub.kdmc.exception.UserExistsInSystem;
import com.byteclub.kdmc.mapper.StudentMapper;
import com.byteclub.kdmc.model.Session;
import com.byteclub.kdmc.model.SessionStatus;
import com.byteclub.kdmc.model.Student;
import com.byteclub.kdmc.repository.SessionRepository;
import com.byteclub.kdmc.repository.StudentRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMapAdapter;
import javax.crypto.SecretKey;
import java.time.LocalDate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {
    private final StudentRepository studentRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final SessionRepository sessionRepository;

    public AuthService(StudentRepository studentRepository, BCryptPasswordEncoder bCryptPasswordEncoder, SessionRepository sessionRepository) {
        this.studentRepository = studentRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.sessionRepository = sessionRepository;
    }

    public Object signUp(SignUpDTO signupDTO) {
        String userType = signupDTO.getUserType();

        Optional<Student> existingStudent = studentRepository.findByEmail(signupDTO.getEmail());
        if (existingStudent.isPresent()) {
            throw new UserExistsInSystem("User with email " + signupDTO.getEmail() + " already exists in system");
        } else {
            Student student = new Student();
            student.setEmail(signupDTO.getEmail());
            student.setPassword(bCryptPasswordEncoder.encode(signupDTO.getPassword()));
            return studentRepository.save(student);
        }
    }

    public ResponseEntity<StudentResponseDTO> login(LoginDTO loginDTO) {
        Optional<Student> student = studentRepository.findByEmail(loginDTO.getEmail());
        if (student.isEmpty()) {
            throw new ResourceNotFoundException(
                    "User with email" + loginDTO.getEmail() + "does not exits in system. Please login");
        }
        if (!bCryptPasswordEncoder.matches(loginDTO.getPassword(), student.get().getPassword())) {
            throw new InvalidCredentials("Invalid Credentials");
        }
        //create a session
        String token = createSession(student);

        MultiValueMapAdapter<String, String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE, token);

        StudentResponseDTO studentResponseDTO = StudentMapper.mapStudentToResponse(student.get());
        return new ResponseEntity<>(studentResponseDTO, headers, HttpStatus.OK);
    }

    private String createSession(Optional<Student> student) {
        //token generation
        //String token = RandomStringUtils.randomAlphanumeric(30);
        MacAlgorithm alg = Jwts.SIG.HS256; // HS256 algo added for JWT
        SecretKey key = alg.key().build(); // generating the secret key

        //start adding the claims
        Map<String, Object> jsonForJWT = new HashMap<>();
        jsonForJWT.put("userId", student.get().getEmail());
        //jsonForJWT.put("roles", student.get().s.getRoles());
        jsonForJWT.put("createdAt", new Date());
        jsonForJWT.put("expiryAt", new Date(LocalDate.now().plusDays(3).toEpochDay()));

        String token = Jwts.builder()
                .claims(jsonForJWT) // added the claims
                .signWith(key, alg) // added the algo and key
                .compact(); //building the token

        //String token = RandomStringUtils.randomAlphanumeric(40);
        Session session = new Session(token, new Date(), new Date(), student.get(), SessionStatus.ACTIVE);

        sessionRepository.save(session);

        return token;
    }

    public ResponseEntity<Void> logout(String token) {
        Optional<Session> session = sessionRepository.findByToken(token);
        if(session.isEmpty() || SessionStatus.ENDED.equals(session.get().getSessionStatus()))
        {
            throw  new InvalidUserSessionException("Invalid Session");
        }
        session.get().setSessionStatus(SessionStatus.ENDED);
        sessionRepository.save(session.get());
        return ResponseEntity.ok().build();
    }
}
