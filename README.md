# Monii — Budget Tracker

Monii is a Flutter personal-finance app for tracking income, expenses, account
balances, and recurring transactions. It stores financial records locally on
the device and provides summaries, spending insights, reminders, and backup
tools.

## Features

### Accounts and transactions

- Create and manage checking, savings, credit card, cash, investment, and
  business accounts.
- Record income and expenses, with categories, notes, and optional receipt
  photos.
- Schedule one-time or recurring transactions: daily, weekly, twice monthly,
  monthly, or yearly.
- Keep future-dated transactions pending until they are due.
- Transfer funds between accounts while keeping both account balances in sync.
- Search, review, edit, and delete transaction records.

### Dashboard and insights

- View account balances and monthly income and expense summaries.
- Browse transaction activity by date in the calendar and search records.
- Review analytics, including category spending, monthly trends, savings, and
  average daily expenses.

### Reminders and settings

- Schedule daily expense-tracking notifications using the device's timezone.
- Add calendar reminders for eligible future transactions, subject to calendar
  access being available.
- Switch between light and dark themes.
- Hide or show account balances where supported in the interface.
- Check for app updates from the configured update feed.

### Backup and restore

- Export app data to a password-protected, encrypted JSON backup file.
- Import a backup from a JSON file.
- Restore by replacing existing data or merging/appending the backup.
- Failed backup-password attempts are rate-limited with a cooldown.

## Data and privacy

Financial records are stored in a local SQLite database managed by Drift. The
app's backup and restore flow operates on files selected by the user. This
project does not include a cloud account or automatic cloud synchronization
service.

## Technology

- Flutter and Dart
- Drift with SQLite for local persistence
- Provider for theme state
- Awesome Notifications and timezone support for scheduled notifications

The source is organized by feature under `lib/features/`, with shared app
startup and UI utilities under `lib/app/` and `lib/core/`.

## Getting started

Install the Flutter SDK and the platform tooling required for your target
device, then run:

```shell
flutter pub get
flutter run
```

Run the test suite with:

```shell
flutter test
```

Some capabilities, such as notifications, calendar access, image selection,
file picking, and over-the-air updates, depend on platform permissions or
device configuration.
