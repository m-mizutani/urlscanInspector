package main

import (
	"os"

	ar "github.com/m-mizutani/AlertResponder/lib"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

type secretValues struct {
	URLScanApiKey string `json:"urlscan_api_key"`
}

// StartInspection is a main function of the inspector.
func StartInspection(task ar.Task) (*ar.ReportPage, error) {
	logger.WithField("task", task).Info("Start inspection")

	var values secretValues
	err := ar.GetSecretValues(os.Getenv("SECRET_ARN"), &values)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to get secrets")
	}

	if task.Attr.Match("remote", "url") {
		return nil, nil
	}

	if task.Attr.Match("remote", "ipaddr") {
		return nil, nil
	}

	logger.Info("nothing to report")

	return nil, nil
}

func main() {
	funcName := os.Getenv("SUBMITTER_NAME")
	funcRegion := os.Getenv("SUBMITTER_REGION")
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})

	ar.Inspect(StartInspection, funcName, funcRegion)
}
