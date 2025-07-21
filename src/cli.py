import argparse

# Import the Detector class that handles log parsing and event discussion
from src.detector import Detector

# Import the Database class that handles storing and querying incidents
from src.database import Database

def main():
    # initialise the argument for command-line interaction
    parser = argparse.ArgumentParser(
        description = "TrackSnipper: CLI Tool for Linux log-based anomaly detection"
    )

    # create subcommands: scna, list and report
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---------------------
    # Subcommand: scan
    # ---------------------
    scan_parser = subparsers.add_parser("scan", help="Scan logs and record incidents")

    # argument to choose between "auth" and "syslog" logs
    scan_parser.add_argument(
        "--log", choices=["auth", "syslog"], required=True,
        help="Specify which log toi scan (auth or syslog)"
    )

    # Optional argument to enable continuous scanning (tailing the log)
    scan_parser.add_argument(
        "--watch", action="store_true",
        help="Continuously watch the log file"
    )


    # ---------------------
    # Subcommand: list
    # ---------------------
    list_parser = subparsers.add_parser("list", help="List recorded incidents")

    # Optional filter to list incidents based on severity level
    list_parser.add_argument(
        "--severity", choices=["low", "medium", "high"],
        help="Filter incidents by severity"
    )


    # ---------------------
    # Subcommand: report
    # ---------------------
    report_parser = subparsers.add_parser("report", help="Generate a summary report")

    # choose the output format for the report
    report_parser.add_argument(
        "--format", choices=["text", "json", "csv", "html"], default="text",
        help="Output format for the report"
    )

    # Optional output path to save the report to a file
    report_parser.add_argument(
        "--output", help="Output file path for the report"
    )

    # parse the arguments
    args = parser.parse_args()

    # initialise the sqlite database and the log detector
    db = Database("incidents.db")
    detector = Detector()

    # ------------------------
    # Execute the chosen command
    # ------------------------

    # handle the scan command
    if args.command == "scan":
        # parse logs and collect incidents
        detector.scan(log_type = args.log, watch = args.watch)
        incidents = detector.get_incidents()

        # store incidents in the database
        db.insert_incidents(incidents)
        print(f"Inserted {len(incidents)} incidents into database.")

    # handle the list command
    elif args.command == "list":
        # retrieve and print incidents from DB
        incidents = db.list_incidents(severity = args.severity)
        for inc in incidents:
            print(inc)

    # handle the report command
    elif args.command == "report":
        # generate and print or save the report
        report = db.generate_report(fmt = args.format)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            
            print(f"Report saved to {args.output}")
        else:
            print(report)


# entry point for CLI script
if __name__ == "__main__":
    main()
