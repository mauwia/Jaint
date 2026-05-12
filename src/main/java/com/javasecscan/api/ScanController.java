package com.javasecscan.api;

import com.javasecscan.analysis.SarifFormatter;
import com.javasecscan.api.dto.FindingDto;
import com.javasecscan.api.dto.ScanResponse;
import com.javasecscan.domain.Scan;
import com.javasecscan.service.ScanService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/scans")
@Tag(name = "Scans", description = "Submit jars for analysis and retrieve findings")
public class ScanController {

    private final ScanService scanService;
    private final SarifFormatter sarifFormatter;

    public ScanController(ScanService scanService, SarifFormatter sarifFormatter) {
        this.scanService = scanService;
        this.sarifFormatter = sarifFormatter;
    }

    @PostMapping
    @Operation(summary = "Submit a JAR for scanning",
            description = "Stores the JAR and dispatches an asynchronous scan. "
                    + "Poll GET /api/scans/{id} for status and findings.")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Scan accepted, processing asynchronously"),
            @ApiResponse(responseCode = "400", description = "Invalid file (not a .jar or empty)",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<ScanResponse> submit(
            @Parameter(description = "Java archive (.jar) to scan", required = true)
            @RequestParam("file") MultipartFile file) throws IOException {
        Scan scan = scanService.submit(file);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(ScanResponse.from(scan, false));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Retrieve a scan report",
            description = "Returns the scan record and all findings. Pass `format=sarif` "
                    + "to get a SARIF 2.1.0 document instead of the native JSON shape.")
    public Object get(
            @PathVariable Long id,
            @Parameter(description = "Output format: `json` (default) or `sarif`")
            @RequestParam(value = "format", required = false) String format) {
        Scan scan = scanService.get(id);
        if ("sarif".equalsIgnoreCase(format)) {
            return sarifFormatter.fromScan(scan);
        }
        return ScanResponse.from(scan, true);
    }

    @GetMapping
    @Operation(summary = "List all scans (without findings)")
    public List<ScanResponse> list() {
        return scanService.list().stream()
                .map(s -> ScanResponse.from(s, false))
                .collect(Collectors.toList());
    }

    @GetMapping("/{id}/diff")
    @Operation(summary = "Diff two scans",
            description = "Returns findings present in scan {id} that are NOT present in `against`. "
                    + "Useful as a PR gate to flag only newly-introduced vulnerabilities. "
                    + "Findings are matched on (ruleId, enclosingClass, enclosingMethod) — line "
                    + "shifts from cosmetic edits do not count as new findings.")
    public DiffResponse diff(
            @PathVariable Long id,
            @Parameter(description = "Baseline scan ID to compare against", required = true)
            @RequestParam("against") Long against) {
        List<FindingDto> introduced = scanService.diff(against, id);
        List<FindingDto> resolved = scanService.diff(id, against);
        return new DiffResponse(id, against, introduced, resolved);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
    }

    public record ErrorResponse(String error) {}

    public record DiffResponse(Long scanId,
                               Long baselineScanId,
                               List<FindingDto> introduced,
                               List<FindingDto> resolved) {}
}
