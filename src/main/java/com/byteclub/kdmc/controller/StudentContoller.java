package com.byteclub.kdmc.controller;

import com.byteclub.kdmc.dto.StudentRequestDTO;
import com.byteclub.kdmc.dto.StudentResponseDTO;
import com.byteclub.kdmc.model.Student;
import com.byteclub.kdmc.service.StudentService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;
import java.util.Optional;
import java.util.UUID;


@RestController
@RequestMapping("/v1")
public class StudentContoller {
    private StudentService studentService;

    public StudentContoller(StudentService studentService) {
        this.studentService = studentService;
    }

    @GetMapping("/student/{Id}")
    public ResponseEntity<Student> getStudentById(@RequestParam String Id) {
        UUID uuid = UUID.fromString(Id);
        Optional<Student> student = studentService.findStudentById(uuid);
        return new ResponseEntity<>(student.get(), HttpStatus.OK);

    }

    @PostMapping("/student")
    public ResponseEntity<StudentResponseDTO> saveStudent(@RequestBody StudentRequestDTO studentRequestDTO) {
        StudentResponseDTO student = studentService.save(studentRequestDTO);
        return ResponseEntity.ok(student);
    }

    @GetMapping("/students")
    public ResponseEntity<List<StudentResponseDTO>> getAllStudents()
    {
        return ResponseEntity.ok(studentService.findAllStudent());
    }
}
