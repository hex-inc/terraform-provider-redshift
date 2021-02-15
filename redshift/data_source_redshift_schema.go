package redshift

import (
	"log"
	"strconv"

	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceRedshiftSchema() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceRedshiftSchemaReadByName,

		Schema: map[string]*schema.Schema{
			"database": {
				Type:     schema.TypeString,
				Required: true,
			},
			"schema_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"owner": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func dataSourceRedshiftSchemaReadByName(d *schema.ResourceData, meta interface{}) error {
	var (
		oid   int
		owner int
	)

	name := d.Get("schema_name").(string)
	redshiftClient, dbErr := meta.(*Client).getConnection(d.Get("database").(string))

	if dbErr != nil {
		log.Print(dbErr)
		return dbErr
	}

	err := redshiftClient.QueryRow("select oid, nspowner from pg_namespace where nspname = $1", name).Scan(&oid, &owner)

	if err != nil {
		log.Print(err)
		return err
	}

	d.SetId(strconv.Itoa(oid))
	d.Set("owner", owner)

	return err
}
