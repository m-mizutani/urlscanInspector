package main

import (
	"fmt"
	"os"
	"time"

	ar "github.com/m-mizutani/AlertResponder/lib"
	"github.com/m-mizutani/urlscan-go/urlscan"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

type secretValues struct {
	URLScanAPIKey string `json:"urlscan_api_key"`
}

func inspectIPAddr(task ar.Task, secrets secretValues) (*ar.ReportPage, error) {
	client := urlscan.NewClient(secrets.URLScanAPIKey)

	resp, err := client.Search(urlscan.SearchArguments{
		Query: urlscan.String(fmt.Sprintf("ip:%s", task.Attr.Value)),
		Sort:  urlscan.String("timestamp:desc"),
		Size:  urlscan.Uint64(10),
	})

	if err != nil {
		return nil, errors.Wrap(err, "Fail to search urlscan.io result")
	}

	host := ar.ReportOpponentHost{}
	logger.WithField("results", resp.Results).Info("urlscan.io results")

	for _, result := range resp.Results {
		ts, err := time.Parse("2006-01-02T15:04:05.000Z", result.Task.Time)
		if err != nil {
			ts = time.Time{} // set empty time
		}

		p := ar.ReportURL{
			URL:       result.Page.URL,
			Timestamp: ts,
			Reference: fmt.Sprintf("https://urlscan.io/result/%s/", result.ID),
			Source:    "urlscan.io",
		}
		host.RelatedURLs = append(host.RelatedURLs, p)

		logger.WithField("report", p).Info("Add page")
	}

	page := ar.NewReportPage()
	page.OpponentHosts = append(page.OpponentHosts, host)

	return &page, nil
}

func inspectURL(task ar.Task, secrets secretValues) (*ar.ReportPage, error) {
	return nil, nil
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
		return inspectURL(task, values)
	}

	if task.Attr.Match("remote", "ipaddr") {
		return inspectIPAddr(task, values)
	}

	logger.Info("nothing to report")

	return nil, nil
}

func main() {
	funcName := os.Getenv("SUBMITTER_NAME")
	funcRegion := os.Getenv("SUBMITTER_REGION")
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})

	urlscan.Logger = logger

	ar.Inspect(StartInspection, funcName, funcRegion)
}
