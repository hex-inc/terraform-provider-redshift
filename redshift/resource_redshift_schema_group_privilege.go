package redshift

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
)

//https://docs.aws.amazon.com/redshift/latest/dg/r_GRANT.html
//https://docs.aws.amazon.com/redshift/latest/dg/r_REVOKE.html

/*
TODO Id is schema_id || '_' || group_id, not sure if that is consistent for terraform --frankfarrell
*/
func redshiftSchemaGroupPrivilege() *schema.Resource {
	return &schema.Resource{
		Create: resourceRedshiftSchemaGroupPrivilegeCreate,
		Read:   resourceRedshiftSchemaGroupPrivilegeRead,
		Update: resourceRedshiftSchemaGroupPrivilegeUpdate,
		Delete: resourceRedshiftSchemaGroupPrivilegeDelete,
		Exists: resourceRedshiftSchemaGroupPrivilegeExists,
		Importer: &schema.ResourceImporter{
			State: resourceRedshiftSchemaGroupPrivilegeImport,
		},

		Schema: map[string]*schema.Schema{
			"schema_id": {
				Type:     schema.TypeInt,
				Required: true,
				ForceNew: true,
			},
			"group_id": {
				Type:     schema.TypeInt,
				Required: true,
				ForceNew: true,
			},
			"select": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"insert": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"update": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"delete": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"references": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"create": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"usage": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
	}
}

func resourceRedshiftSchemaGroupPrivilegeExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	// Exists - This is called to verify a resource still exists. It is called prior to Read,
	// and lowers the burden of Read to be able to assume the resource exists.
	client := meta.(*Client).db

	var privilegeId string

	err := client.QueryRow(`select nsp.oid || '_' || pu.grosysid as id
		from pg_group pu, pg_namespace nsp
		where array_to_string(nsp.nspacl, '|') LIKE '%' || 'group ' || pu.groname || '=%'
			and nsp.oid || '_' || pu.grosysid = $1`,
		d.Id()).Scan(&privilegeId)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

func resourceRedshiftSchemaGroupPrivilegeCreate(d *schema.ResourceData, meta interface{}) error {

	redshiftClient := meta.(*Client).db

	tx, txErr := redshiftClient.Begin()

	if txErr != nil {
		panic(txErr)
	}

	grants := validateGrants(d)
	schemaGrants := validateSchemaGrants(d)

	if len(grants) == 0 && len(schemaGrants) == 0 {
		tx.Rollback()
		return NewError("Must have at least 1 privilege")
	}

	schemaName, schemaOwner, schemaErr := GetSchemaInfoForSchemaId(tx, d.Get("schema_id").(int))
	if schemaErr != nil {
		log.Print(schemaErr)
		tx.Rollback()
		return schemaErr
	}

	if isSystemSchema(schemaOwner) && schemaName != "public" {
		tx.Rollback()
		return NewError("Privilege creation is not allowed for system schemas, schema=" + schemaName)
	}

	groupName, groupErr := GetGroupNameForGroupId(tx, d.Get("group_id").(int))
	if groupErr != nil {
		log.Print(groupErr)
		tx.Rollback()
		return groupErr
	}

	if len(grants) > 0 {
		var grantPrivilegeStatement = "GRANT " + strings.Join(grants[:], ",") + " ON ALL TABLES IN SCHEMA " + schemaName + " TO GROUP " + groupName

		if _, err := tx.Exec(grantPrivilegeStatement); err != nil {
			log.Print(err)
			tx.Rollback()
			return err
		}
	}

	if len(schemaGrants) > 0 {
		var grantPrivilegeSchemaStatement = "GRANT " + strings.Join(schemaGrants[:], ",") + " ON SCHEMA " + schemaName + " TO GROUP " + groupName
		if _, err := tx.Exec(grantPrivilegeSchemaStatement); err != nil {
			log.Print(err)
			tx.Rollback()
			return err
		}
	}

	d.SetId(fmt.Sprint(d.Get("schema_id").(int)) + "_" + fmt.Sprint(d.Get("group_id").(int)))

	readErr := readRedshiftSchemaGroupPrivilege(d, tx)

	if readErr != nil {
		tx.Rollback()
		return readErr
	}

	tx.Commit()
	return nil
}

func resourceRedshiftSchemaGroupPrivilegeRead(d *schema.ResourceData, meta interface{}) error {

	redshiftClient := meta.(*Client).db
	tx, txErr := redshiftClient.Begin()
	if txErr != nil {
		panic(txErr)
	}

	err := readRedshiftSchemaGroupPrivilege(d, tx)

	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func readRedshiftSchemaGroupPrivilege(d *schema.ResourceData, tx *sql.Tx) error {
	var (
		usagePrivilege      bool
		createPrivilege     bool
		selectPrivilege     float32
		updatePrivilege     float32
		insertPrivilege     float32
		deletePrivilege     float32
		referencesPrivilege float32
	)

	var hasSchemaPrivilegeQuery = `
			select
			case
				when charindex('U',split_part(split_part(array_to_string(nspacl, '|'), 'group ' || pu.groname,2 ) ,'/',1)) > 0 then 1
				else 0
			end as usage,
			case
				when charindex('C',split_part(split_part(array_to_string(nspacl, '|'),'group ' || pu.groname,2 ) ,'/',1)) > 0 then 1
				else 0
			end as create
			from pg_group pu, pg_namespace nsp
			where array_to_string(nsp.nspacl, '|') LIKE '%' || 'group ' || pu.groname || '=%'
			and nsp.oid = $1
			and pu.grosysid = $2`

	schemaPrivilegesError := tx.QueryRow(hasSchemaPrivilegeQuery, d.Get("schema_id").(int), d.Get("group_id").(int)).Scan(&usagePrivilege, &createPrivilege)

	if schemaPrivilegesError != nil && schemaPrivilegesError != sql.ErrNoRows {
		tx.Rollback()
		return schemaPrivilegesError
	}

	d.Set("usage", usagePrivilege)
	d.Set("create", createPrivilege)

	var hasTablePrivilegeQuery = `
		SELECT
			coalesce(avg(decode(charindex ('r', split_part(split_part(array_to_string(cls.relacl, '|'), 'group ' || $2, 2), '/', 1)), 0, 0, 1)), 0.5) AS "select",
			coalesce(avg(decode(charindex ('w', split_part(split_part(array_to_string(cls.relacl, '|'), 'group ' || $2, 2), '/', 1)), 0, 0, 1)), 0.5) AS "update",
			coalesce(avg(decode(charindex ('a', split_part(split_part(array_to_string(cls.relacl, '|'), 'group ' || $2, 2), '/', 1)), 0, 0, 1)), 0.5) AS "insert",
			coalesce(avg(decode(charindex ('d', split_part(split_part(array_to_string(cls.relacl, '|'), 'group ' || $2, 2), '/', 1)), 0, 0, 1)), 0.5) AS "delete",
			coalesce(avg(decode(charindex ('x', split_part(split_part(array_to_string(cls.relacl, '|'), 'group ' || $2, 2), '/', 1)), 0, 0, 1)), 0.5) AS "references"
		FROM
			pg_user use
			LEFT JOIN pg_class cls ON cls.relowner = use.usesysid
		WHERE
			cls.relnamespace = $1;
	`

	tablePrivilegesError := tx.QueryRow(hasTablePrivilegeQuery, d.Get("schema_id").(int), d.Get("group_id").(int)).Scan(&selectPrivilege, &updatePrivilege, &insertPrivilege, &deletePrivilege, &referencesPrivilege)

	if tablePrivilegesError != nil && tablePrivilegesError != sql.ErrNoRows {
		tx.Rollback()
		return tablePrivilegesError
	}

	if selectPrivilege >= 1 {
		d.Set("select", true)
	} else if selectPrivilege <= 0 {
		d.Set("select", false)
	} else {
		d.Set("select", !d.Get("select").(bool))
	}

	if insertPrivilege >= 1 {
		d.Set("insert", true)
	} else if insertPrivilege <= 0 {
		d.Set("insert", false)
	} else {
		d.Set("select", !d.Get("select").(bool))
	}

	if updatePrivilege >= 1 {
		d.Set("update", true)
	} else if updatePrivilege <= 0 {
		d.Set("update", false)
	} else {
		d.Set("update", !d.Get("update").(bool))
	}

	if deletePrivilege >= 1 {
		d.Set("delete", true)
	} else if deletePrivilege <= 0 {
		d.Set("delete", false)
	} else {
		d.Set("delete", !d.Get("delete").(bool))
	}

	if referencesPrivilege >= 1 {
		d.Set("references", true)
	} else if referencesPrivilege <= 0 {
		d.Set("references", false)
	} else {
		d.Set("references", !d.Get("references").(bool))
	}

	return nil
}

func resourceRedshiftSchemaGroupPrivilegeUpdate(d *schema.ResourceData, meta interface{}) error {
	redshiftClient := meta.(*Client).db
	tx, txErr := redshiftClient.Begin()

	if txErr != nil {
		panic(txErr)
	}

	grants := validateGrants(d)
	schemaGrants := validateSchemaGrants(d)

	if len(grants) == 0 && len(schemaGrants) == 0 {
		tx.Rollback()
		return NewError("Must have at least 1 privilege")
	}

	schemaName, _, schemaErr := GetSchemaInfoForSchemaId(tx, d.Get("schema_id").(int))
	if schemaErr != nil {
		log.Print(schemaErr)
		tx.Rollback()
		return schemaErr
	}

	groupName, groupErr := GetGroupNameForGroupId(tx, d.Get("group_id").(int))
	if groupErr != nil {
		log.Print(groupErr)
		tx.Rollback()
		return groupErr
	}

	//Would be much nicer to do this with zip if possible
	if err := updatePrivilege(tx, d, "select", "SELECT", schemaName, groupName); err != nil {
		tx.Rollback()
		return err
	}
	if err := updatePrivilege(tx, d, "insert", "INSERT", schemaName, groupName); err != nil {
		tx.Rollback()
		return err
	}
	if err := updatePrivilege(tx, d, "update", "UPDATE", schemaName, groupName); err != nil {
		tx.Rollback()
		return err
	}
	if err := updatePrivilege(tx, d, "delete", "DELETE", schemaName, groupName); err != nil {
		tx.Rollback()
		return err
	}
	if err := updatePrivilege(tx, d, "references", "REFERENCES", schemaName, groupName); err != nil {
		tx.Rollback()
		return err
	}
	if err := updateSchemaPrivilege(tx, d, "usage", "USAGE", schemaName, groupName); err != nil {
		tx.Rollback()
		return err
	}
	if err := updateSchemaPrivilege(tx, d, "create", "CREATE", schemaName, groupName); err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func resourceRedshiftSchemaGroupPrivilegeDelete(d *schema.ResourceData, meta interface{}) error {

	redshiftClient := meta.(*Client).db
	tx, txErr := redshiftClient.Begin()

	if txErr != nil {
		panic(txErr)
	}

	schemaName, _, schemaErr := GetSchemaInfoForSchemaId(tx, d.Get("schema_id").(int))
	if schemaErr != nil {
		log.Print(schemaErr)
		tx.Rollback()
		return schemaErr
	}

	groupName, groupErr := GetGroupNameForGroupId(tx, d.Get("group_id").(int))
	if groupErr != nil {
		log.Print(groupErr)
		tx.Rollback()
		return groupErr
	}
	if _, err := tx.Exec("REVOKE ALL ON ALL TABLES IN SCHEMA " + schemaName + " FROM GROUP " + groupName); err != nil {
		tx.Rollback()
		return err
	}

	if _, err := tx.Exec("REVOKE ALL ON SCHEMA " + schemaName + " FROM GROUP " + groupName); err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func resourceRedshiftSchemaGroupPrivilegeImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	if err := resourceRedshiftSchemaGroupPrivilegeRead(d, meta); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}

func updatePrivilege(tx *sql.Tx, d *schema.ResourceData, attribute string, privilege string, schemaName string, groupName string) error {
	if !d.HasChange(attribute) {
		return nil
	}

	if d.Get(attribute).(bool) {
		if _, err := tx.Exec("GRANT " + privilege + " ON ALL TABLES IN SCHEMA " + schemaName + " TO GROUP " + groupName); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec("REVOKE " + privilege + " ON ALL TABLES IN SCHEMA " + schemaName + " FROM GROUP " + groupName); err != nil {
			return err
		}
	}
	return nil
}

func updateSchemaPrivilege(tx *sql.Tx, d *schema.ResourceData, attribute string, privilege string, schemaName string, groupName string) error {
	if !d.HasChange(attribute) {
		return nil
	}

	if d.Get(attribute).(bool) {
		if _, err := tx.Exec("GRANT " + privilege + " ON SCHEMA " + schemaName + " TO GROUP " + groupName); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec("REVOKE " + privilege + " ON SCHEMA " + schemaName + " FROM GROUP " + groupName); err != nil {
			return err
		}
	}
	return nil
}
