package redshift

import (
	"github.com/hashicorp/terraform/helper/schema"
)

// errorString is a trivial implementation of error.
type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

// NewError returns an error that formats as the given text.
func NewError(text string) error {
	return &errorString{text}
}

func isSystemSchema(schemaOwner int) bool {
	return schemaOwner == 1
}

func validateSchemaGrants(d *schema.ResourceData) []string {
	var grants []string

	if v, ok := d.GetOk("create"); ok && v.(bool) {
		grants = append(grants, "CREATE")
	}
	if v, ok := d.GetOk("usage"); ok && v.(bool) {
		grants = append(grants, "USAGE")
	}

	return grants
}

func validateGrants(d *schema.ResourceData) []string {
	var grants []string

	if v, ok := d.GetOk("select"); ok && v.(bool) {
		grants = append(grants, "SELECT")
	}
	if v, ok := d.GetOk("insert"); ok && v.(bool) {
		grants = append(grants, "INSERT")
	}
	if v, ok := d.GetOk("update"); ok && v.(bool) {
		grants = append(grants, "UPDATE")
	}
	if v, ok := d.GetOk("delete"); ok && v.(bool) {
		grants = append(grants, "DELETE")
	}
	if v, ok := d.GetOk("references"); ok && v.(bool) {
		grants = append(grants, "REFERENCES")
	}

	return grants
}
