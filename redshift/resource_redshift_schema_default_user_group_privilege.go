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
TODO Id is schema_id || '_' || group_id || '_' || owner_id, not sure if that is consistent for terraform --frankfarrell
*/
func redshiftSchemaDefaultUserGroupPrivilege() *schema.Resource {
	return &schema.Resource{
		Create: resourceRedshiftSchemaDefaultUserGroupPrivilegeCreate,
		Read:   resourceRedshiftSchemaDefaultUserGroupPrivilegeRead,
		Update: resourceRedshiftSchemaDefaultUserGroupPrivilegeUpdate,
		Delete: resourceRedshiftSchemaDefaultUserGroupPrivilegeDelete,
		Exists: resourceRedshiftSchemaDefaultUserGroupPrivilegeExists,
		Importer: &schema.ResourceImporter{
			State: resourceRedshiftSchemaDefaultUserGroupPrivilegeImport,
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
			"owner_id": {
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
		},
	}
}

func resourceRedshiftSchemaDefaultUserGroupPrivilegeExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	// Exists - This is called to verify a resource still exists. It is called prior to Read,
	// and lowers the burden of Read to be able to assume the resource exists.
	client := meta.(*Client).db

	var privilegeId string

	err := client.QueryRow(`select nsp.oid || '_' || pu.grosysid || '_' || acl.defacluser as id
		from pg_group pu, pg_default_acl acl, pg_namespace nsp
		where acl.defaclnamespace = nsp.oid
		and array_to_string(acl.defaclacl, '|') LIKE '%' || 'group ' || pu.groname || '=%'
		and nsp.oid || '_' || pu.grosysid || '_' || acl.defacluser = $1`,
		d.Id()).Scan(&privilegeId)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

func resourceRedshiftSchemaDefaultUserGroupPrivilegeCreate(d *schema.ResourceData, meta interface{}) error {

	redshiftClient := meta.(*Client).db

	tx, txErr := redshiftClient.Begin()

	if txErr != nil {
		panic(txErr)
	}

	grants := validateGrants(d)

	if len(grants) == 0 {
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
		var defaultPrivilegesStatement = "ALTER DEFAULT PRIVILEGES"

		//If no owner is specified it defaults to client user
		if v, ok := d.GetOk("owner_id"); ok {
			var usernames = GetUsersnamesForUsesysid(redshiftClient, []interface{}{v.(int)})
			defaultPrivilegesStatement += " FOR USER " + usernames[0]
		}

		defaultPrivilegesStatement += " IN SCHEMA " + schemaName + " GRANT " + strings.Join(grants[:], ",") + " ON TABLES TO GROUP " + groupName
		if _, err := tx.Exec(defaultPrivilegesStatement); err != nil {
			log.Print(err)
			tx.Rollback()
			return err
		}
	}

	d.SetId(fmt.Sprint(d.Get("schema_id").(int)) + "_" + fmt.Sprint(d.Get("group_id").(int)) + "_" + fmt.Sprint(d.Get("owner_id").(int)))

	readErr := readRedshiftSchemaDefaultUserGroupPrivilege(d, tx)

	if readErr != nil {
		tx.Rollback()
		return readErr
	}

	tx.Commit()
	return nil
}

func resourceRedshiftSchemaDefaultUserGroupPrivilegeRead(d *schema.ResourceData, meta interface{}) error {

	redshiftClient := meta.(*Client).db
	tx, txErr := redshiftClient.Begin()
	if txErr != nil {
		panic(txErr)
	}

	err := readRedshiftSchemaDefaultUserGroupPrivilege(d, tx)

	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func readRedshiftSchemaDefaultUserGroupPrivilege(d *schema.ResourceData, tx *sql.Tx) error {
	var (
		selectPrivilege     bool
		updatePrivilege     bool
		insertPrivilege     bool
		deletePrivilege     bool
		referencesPrivilege bool
	)

	var hasPrivilegeQuery = `
			select
			decode(charindex('r',split_part(split_part(array_to_string(defaclacl, '|'),'group ' || pu.groname,2 ) ,'/',1)),0,0,1)  as select,
			decode(charindex('w',split_part(split_part(array_to_string(defaclacl, '|'),'group ' || pu.groname,2 ) ,'/',1)),0,0,1)  as update,
			decode(charindex('a',split_part(split_part(array_to_string(defaclacl, '|'),'group ' || pu.groname,2 ) ,'/',1)),0,0,1)  as insert,
			decode(charindex('d',split_part(split_part(array_to_string(defaclacl, '|'),'group ' || pu.groname,2 ) ,'/',1)),0,0,1)  as delete,
			decode(charindex('x',split_part(split_part(array_to_string(defaclacl, '|'),'group ' || pu.groname,2 ) ,'/',1)),0,0,1)  as references
			from pg_group pu, pg_default_acl acl, pg_namespace nsp
			where acl.defaclnamespace = nsp.oid and
			array_to_string(acl.defaclacl, '|') LIKE '%' || 'group ' || pu.groname || '=%'
			and nsp.oid = $1
			and pu.grosysid = $2
			and acl.defacluser = $3`

	privilegesError := tx.QueryRow(hasPrivilegeQuery, d.Get("schema_id").(int), d.Get("group_id").(int), d.Get("owner_id").(int)).Scan(&selectPrivilege, &updatePrivilege, &insertPrivilege, &deletePrivilege, &referencesPrivilege)

	if privilegesError != nil && privilegesError != sql.ErrNoRows {
		tx.Rollback()
		return privilegesError
	}

	d.Set("select", selectPrivilege)
	d.Set("insert", insertPrivilege)
	d.Set("update", updatePrivilege)
	d.Set("delete", deletePrivilege)
	d.Set("references", referencesPrivilege)

	return nil
}

func resourceRedshiftSchemaDefaultUserGroupPrivilegeUpdate(d *schema.ResourceData, meta interface{}) error {
	redshiftClient := meta.(*Client).db
	tx, txErr := redshiftClient.Begin()

	if txErr != nil {
		panic(txErr)
	}

	grants := validateGrants(d)

	if len(grants) == 0 {
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

	var username string

	//If no owner is specified it defaults to client user
	if v, ok := d.GetOk("owner_id"); ok {
		var usernames = GetUsersnamesForUsesysid(redshiftClient, []interface{}{v.(int)})
		username = usernames[0]
	}

	//Would be much nicer to do this with zip if possible
	if err := updateUserGroupDefaultPrivilege(tx, d, "select", "SELECT", schemaName, groupName, username); err != nil {
		tx.Rollback()
		return err
	}
	if err := updateUserGroupDefaultPrivilege(tx, d, "insert", "INSERT", schemaName, groupName, username); err != nil {
		tx.Rollback()
		return err
	}
	if err := updateUserGroupDefaultPrivilege(tx, d, "update", "UPDATE", schemaName, groupName, username); err != nil {
		tx.Rollback()
		return err
	}
	if err := updateUserGroupDefaultPrivilege(tx, d, "delete", "DELETE", schemaName, groupName, username); err != nil {
		tx.Rollback()
		return err
	}
	if err := updateUserGroupDefaultPrivilege(tx, d, "references", "REFERENCES", schemaName, groupName, username); err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func resourceRedshiftSchemaDefaultUserGroupPrivilegeDelete(d *schema.ResourceData, meta interface{}) error {

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

	var defaultPrivilegesStatement = "ALTER DEFAULT PRIVILEGES"

	if v, ok := d.GetOk("owner_id"); ok {
		var usernames = GetUsersnamesForUsesysid(redshiftClient, []interface{}{v.(int)})
		defaultPrivilegesStatement += " FOR USER " + usernames[0]
	}

	if _, err := tx.Exec(defaultPrivilegesStatement + " IN SCHEMA " + schemaName + " REVOKE ALL ON TABLES FROM GROUP " + groupName); err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func resourceRedshiftSchemaDefaultUserGroupPrivilegeImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	if err := resourceRedshiftSchemaDefaultUserGroupPrivilegeRead(d, meta); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}

func updateUserGroupDefaultPrivilege(tx *sql.Tx, d *schema.ResourceData, attribute string, privilege string, schemaName string, groupName string, userName string) error {
	if !d.HasChange(attribute) {
		return nil
	}

	if d.Get(attribute).(bool) {
		if _, err := tx.Exec("ALTER DEFAULT PRIVILEGES FOR USER " + userName + " IN SCHEMA " + schemaName + " GRANT " + privilege + " ON TABLES TO GROUP " + groupName); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec("ALTER DEFAULT PRIVILEGES FOR USER " + userName + " IN SCHEMA " + schemaName + " REVOKE " + privilege + " ON TABLES FROM GROUP " + groupName); err != nil {
			return err
		}
	}
	return nil
}
