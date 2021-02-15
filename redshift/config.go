package redshift

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

// Config holds API and APP keys to authenticate to Datadog.
type Config struct {
	url      string
	user     string
	password string
	port     string
	sslmode  string
}

type Client struct {
	config        Config
	getConnection func(database string) (*sql.DB, error)
}

// New redshift client
func (c *Config) Client() *Client {

	connections := make(map[string]*sql.DB)

	getConnection := func(database string) (*sql.DB, error) {
		if connections[database] == nil {
			conninfo := fmt.Sprintf("sslmode=%v user=%v password=%v host=%v port=%v dbname=%v",
				c.sslmode,
				c.user,
				c.password,
				c.url,
				c.port,
				database)

			db, err := sql.Open("postgres", conninfo)
			if err != nil {
				db.Close()
				return nil, err
			}
			return db, nil
		} else {
			return connections[database], nil
		}
	}

	client := Client{
		config:        *c,
		getConnection: getConnection,
	}

	return &client
}

//When do we close the connection?
