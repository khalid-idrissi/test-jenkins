pipeline {
    agent any
    environment {
		netboxtoken = credentials('netboxtoken')
		tokenpywire = credentials('tokenpywire')
		token = credentials('token')
    }
    stages {
        stage('Intsall Packages') {
            steps {
				echo "Intsall Packages"
				bat 'pip install requests'
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat "python jenkins.py ${netboxtoken} ${tokenpywire} ${token}"

            }
        }
    }
}