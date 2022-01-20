package tablewriter

import (
	"os"

	"github.com/olekukonko/tablewriter"
)

func PrintTable(headers []string, data [][]string) {
	FPrintTable(os.Stdout, headers, data)
}

func FPrintTable(out *os.File, headers []string, data [][]string) {
	t := tablewriter.NewWriter(out)
	t.SetHeader(headers)
	t.AppendBulk(data)
	t.Render()
}

type TableWriter interface {
	TableGetHeader() []string
	TableGetRow() []string
}

func PrintTableData(data []TableWriter) {
	FPrintTableData(os.Stdout, data)
}

func FPrintTableData(out *os.File, data []TableWriter) {
	if len(data) == 0 {
		return
	}
	h := data[0].TableGetHeader()
	d := make([][]string, len(data))
	for i, dd := range data {
		d[i] = dd.TableGetRow()
	}
	FPrintTable(out, h, d)
}
