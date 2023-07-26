pipeline {
    agent any
    environment {
		netboxtoken = credentials('netboxtoken')
		tokenpywire = credentials('tokenpywire')
		tokenatlassian = credentials('atlassiantoken')
		secretfile = credentials('SECRET_FILE')
    }
    stages {
        stage('Intsall Packages') {
            steps {
                echo "Intsall Packages"
                bat '"C:\\Program Files\\Python311\\Scripts\\pip.exe" install pynetbox'
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat "C:\\Python311\\python.exe jenkins.py ${netboxtoken} ${tokenpywire} ${tokenatlassian} ${secretfile}"

            }
        }
    }
}

