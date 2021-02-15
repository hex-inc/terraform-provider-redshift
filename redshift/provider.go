package redshift

import (
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": {
				Type:        schema.TypeString,
				Description: "Redshift url",
				Required:    true,
			},
			"user": {
				Type:        schema.TypeString,
				Description: "master user",
				Required:    true,
			},
			"password": {
				Type:        schema.TypeString,
				Description: "master password",
				Required:    true,
				Sensitive:   true,
			},
			"port": {
				Type:        schema.TypeString,
				Description: "port",
				Optional:    true,
				Default:     "5439",
			},
			"sslmode": {
				Type:        schema.TypeString,
				Description: "SSL mode (require, disable, verify-ca, verify-full)",
				Optional:    true,
				Default:     "require",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"redshift_user":                                redshiftUser(),
			"redshift_group":                               redshiftGroup(),
			"redshift_database":                            redshiftDatabase(),
			"redshift_schema":                              redshiftSchema(),
			"redshift_schema_group_privilege":              redshiftSchemaGroupPrivilege(),
			"redshift_schema_default_user_group_privilege": redshiftSchemaDefaultUserGroupPrivilege(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"redshift_schema": dataSourceRedshiftSchema(),
		},
		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {

	config := Config{
		url:      d.Get("url").(string),
		user:     d.Get("user").(string),
		password: d.Get("password").(string),
		port:     d.Get("port").(string),
		sslmode:  d.Get("sslmode").(string),
	}

	client := config.Client()

	return client, nil
}
