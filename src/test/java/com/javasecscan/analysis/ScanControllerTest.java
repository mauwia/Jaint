package com.javasecscan.analysis;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ScanControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void rejectsNonJarUpload() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "evil.txt", MediaType.TEXT_PLAIN_VALUE, "not a jar".getBytes());

        mvc.perform(multipart("/api/scans").file(file))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void rejectsEmptyUpload() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "empty.jar", "application/java-archive", new byte[0]);

        mvc.perform(multipart("/api/scans").file(file))
                .andExpect(status().isBadRequest());
    }
}
