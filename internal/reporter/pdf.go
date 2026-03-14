package reporter

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/security-scanner/security-scanner/internal/models"
)

// PDFReporter generates a PDF report by rendering the HTML report and
// converting it to PDF using wkhtmltopdf.
type PDFReporter struct{}

// WkhtmltopdfAvailable checks whether wkhtmltopdf is installed.
func WkhtmltopdfAvailable() bool {
	_, err := exec.LookPath("wkhtmltopdf")
	return err == nil
}

func (r *PDFReporter) Report(result *models.ScanResult, w io.Writer) error {
	if !WkhtmltopdfAvailable() {
		return fmt.Errorf(
			"wkhtmltopdf is not installed; it is required for PDF output\n\n" +
				"  brew install --cask wkhtmltopdf   # macOS\n" +
				"  apt-get install wkhtmltopdf        # Debian/Ubuntu\n" +
				"  yum install wkhtmltopdf            # RHEL/CentOS\n\n" +
				"Alternatively, use --format html and convert the HTML file manually")
	}

	// Step 1: Render the HTML report into a buffer.
	var htmlBuf bytes.Buffer
	htmlReporter := &HTMLReporter{}
	if err := htmlReporter.Report(result, &htmlBuf); err != nil {
		return fmt.Errorf("HTML rendering failed: %w", err)
	}

	// Step 2: Write HTML to a temp file (wkhtmltopdf reads from a file).
	tmpHTML, err := os.CreateTemp("", "security-scanner-*.html")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	defer os.Remove(tmpHTML.Name())

	if _, err := tmpHTML.Write(htmlBuf.Bytes()); err != nil {
		tmpHTML.Close()
		return fmt.Errorf("cannot write temp HTML: %w", err)
	}
	tmpHTML.Close()

	// Step 3: Create a temp file for the PDF output.
	tmpPDF, err := os.CreateTemp("", "security-scanner-*.pdf")
	if err != nil {
		return fmt.Errorf("cannot create temp PDF file: %w", err)
	}
	defer os.Remove(tmpPDF.Name())
	tmpPDF.Close()

	// Step 4: Convert HTML → PDF via wkhtmltopdf.
	cmd := exec.Command("wkhtmltopdf",
		"--quiet",
		"--enable-local-file-access",
		"--page-size", "A4",
		"--margin-top", "10mm",
		"--margin-bottom", "10mm",
		"--margin-left", "10mm",
		"--margin-right", "10mm",
		"--encoding", "UTF-8",
		"--print-media-type",
		tmpHTML.Name(),
		tmpPDF.Name(),
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wkhtmltopdf conversion failed: %w", err)
	}

	// Step 5: Read the generated PDF and write to the output writer.
	pdfData, err := os.ReadFile(tmpPDF.Name())
	if err != nil {
		return fmt.Errorf("cannot read generated PDF: %w", err)
	}

	if _, err := w.Write(pdfData); err != nil {
		return fmt.Errorf("cannot write PDF output: %w", err)
	}

	return nil
}
